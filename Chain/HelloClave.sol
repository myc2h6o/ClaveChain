pragma solidity ^0.4.0;
import "github.com/mycspring/ClaveChain/Chain/ClaveChain.sol";

contract HelloClave
{
    bytes4 callbackSignature = 0x9d8d06b7;
    ClaveChain claveChain;
    string public data;
    function HelloClave(ClaveChain _claveChain) public
    {
        claveChain = _claveChain;
    }
    
    function getOutDataFrom(string uri) public
    {
        claveChain.Register(this, callbackSignature, uri);
    }
    
    function setData(uint64 requestId, string _data) public
    {
        if(msg.sender == address(claveChain))
        {
            data = _data;
        }
    }
}