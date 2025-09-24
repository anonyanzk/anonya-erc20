// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { Script }      from "forge-std/Script.sol";
import { AnonyaERC20 } from "src/AnonyaERC20.sol";

contract DeployAnonya is Script {

    function run() external {
        string memory name   = "Anonya";
        string memory symbol = "NYA";
        uint256 supply       = 1_000_000 * 1e18;
        uint256 cap          = 2_000_000 * 1e18;
        address feeReceiver  = 0x757579A192a9685dB0BcB193e2c748D57583F7df;

        vm.startBroadcast();

        AnonyaERC20 token = new AnonyaERC20(
            name, 
            symbol, 
            supply, 
            cap, 
            feeReceiver
        );

        vm.stopBroadcast();

        console2.log("Anonyan token:", address(token));
    }
}

