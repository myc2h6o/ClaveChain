pragma solidity ^0.4.0;
contract ClaveChain
{
    struct Request
    {
        address requester;
        bytes4 callback;
        string uri;
        bool isDone;
    }
    
    address creator;
    address clave;
    uint64 public currentId;
    mapping (uint64 => Request) public requests;
 
    function ClaveChain(address _clave) public
    {
        creator = msg.sender;
        clave = _clave;
        currentId = 0;
    }

    function Register(address requester, bytes4 callback, string uri) public returns(uint256)
    {
        // [TODO] store eth value
        uint64 id = currentId;
        currentId++;
        requests[id].requester = requester;
        requests[id].callback = callback;
        requests[id].uri = uri;
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
    
    function Send(uint64 id, string uri, string data) public
    {
        // [TODO]send eth to ClaveChain wallet
        if(msg.sender != clave){
            return;
        }

        if(requests[id].isDone)
        {
            return;
        }

        if(sha3(uri) != sha3(requests[id].uri))
        {
            return;    
        }

        address requester = requests[id].requester;
        bytes4 callback = requests[id].callback;
        requester.call(callback, id, data);
    }

    function Kill() public
    {
        if (msg.sender == creator)
            suicide(creator);
    }
}