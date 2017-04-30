pragma solidity ^0.4.0;

contract KycClaveChain
{
    struct Request
    {
        address requester;
        bytes4 callback;
        bytes18 index;
        bool isDone;
    }
    
    address clave;
    uint64 public currentId;
    mapping (uint64 => Request) public requests;
 
    function KycClaveChain(address _clave) public
    {
        clave = _clave;
        currentId = 0;
    }

    function Register(address requester, bytes4 callback, bytes18 index) public returns(uint64)
    {
        // [TODO] store eth value
        uint64 id = currentId;
        currentId++;
        requests[id].requester = requester;
        requests[id].callback = callback;
        requests[id].index = index;
        requests[id].isDone = false;
        return id;
    }

    function Cancel(uint64 id) public
    {
        // [TODO] send eth back
        if(requests[id].requester != msg.sender)
        {
            return;
        }
        
        requests[id].isDone = true;
    }
    
    function SendResult(uint64 id, bytes18 index, bytes32 name, bytes11 phone) public
    {
        // [TODO]send eth to ClaveChain wallet
        if(msg.sender != clave){
            return;
        }

        if(requests[id].isDone)
        {
            return;
        }

        if(index != requests[id].index)
        {
            return;    
        }

        address requester = requests[id].requester;
        bytes4 callback = requests[id].callback;
        
        // [TODO] deal with failing calls
        requester.call(callback, id, index, name, phone);
        
        requests[id].isDone = true;
    }
}
