pragma solidity ^0.4.0;

import "github.com/mycspring/ClaveChain/Chain/IClaveChain.sol";

contract HelloClave is IClaveChain
{
    bytes4 callback = 0x9d8d06b7;
    IClaveChain public claveChain;
    string public data;
    uint64 public reqid;
    function HelloClave(IClaveChain _claveChain) public
    {
        claveChain = _claveChain;
    }
    
    function getOutDataFrom(string uri) public
    {
        reqid = claveChain.Register(this, callback, uri);
    }
    
    function setData(uint64 requestId, string _data) public
    {
        if(msg.sender == address(claveChain))
        {
            data = _data;
        }
    }
}
