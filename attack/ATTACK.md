# Documentation of changes to perform the attack on Common-Prefix

## Attack
- At ledger seqNum  5: transact 1000000000 coins from genesis account to Source-Account
- At ledger seqNum 20 do this simultaniously:
  - transact 1000000000 coins from source-account to account 1
  - transact 1000000000 coins from source-account to account 2

## Accounts
- Genesis Account:  rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh
- Source-Account:   rfhWbXmBpxqjUWfqVv34t4pHJHs6YDFKCN
- Account 1:        rG1eMisac1neCXeZNPYmwV8sovo5vs9dnB
- Account 2:        rnkP5Tipm14sqpoDetQxrLjiyyKhk72eAi

## First attempt
- Create two nodes sharing the same public-/private-keypair (00 and 10)
- do: apt install iputils-ping
- do: sudo tc qdisc add dev veth root netem delay 500ms
- ping validator_10 (from validator_00)
- rippled submit snoPBrXtMeMyMHUVTgbuqAfg1SUTb '{"Account": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh","Amount": "1000000000","Destination": "rfhWbXmBpxqjUWfqVv34t4pHJHs6YDFKCN", "TransactionType": "Payment","Fee": "10" }'
- rippled submit sEd7gsxCwikqZ9C81bjKMFNM9xoReYU '{"Account": "rfhWbXmBpxqjUWfqVv34t4pHJHs6YDFKCN","Amount": "1000000000","Destination": "rG1eMisac1neCXeZNPYmwV8sovo5vs9dnB","TransactionType": "Payment","Fee": "10" }'
- rippled submit sEd7gsxCwikqZ9C81bjKMFNM9xoReYU '{"Account": "rfhWbXmBpxqjUWfqVv34t4pHJHs6YDFKCN","Amount": "1000000000","Destination": "rnkP5Tipm14sqpoDetQxrLjiyyKhk72eAi","TransactionType": "Payment","Fee": "10" }'
