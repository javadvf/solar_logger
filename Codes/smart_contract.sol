/**
 *Submitted for verification at Etherscan.io on 2025-06-05
*/

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SolarLoggerV3 {
    struct LogEntry {
        bytes32 merkleRoot;
        bytes32 batchHash;
        uint256 timestamp;
        bytes32 deviceIdHash;
        string deviceId;
        uint256 cumulativeEnergyWh;
        address submitter;
    }

    LogEntry[] public logs;

    event BatchLogged(
        address indexed submitter,
        uint256 indexed index,
        bytes32 indexed deviceIdHash,
        bytes32 merkleRoot,
        bytes32 batchHash,
        uint256 timestamp,
        string deviceId,
        uint256 cumulativeEnergyWh
    );

    function logBatch(
        bytes32 merkleRoot,
        bytes32 batchHash,
        uint256 timestamp,
        bytes32 deviceIdHash,
        string memory deviceId,
        uint256 cumulativeEnergyWh
    ) external {
        logs.push(LogEntry({
            merkleRoot: merkleRoot,
            batchHash: batchHash,
            timestamp: timestamp,
            deviceIdHash: deviceIdHash,
            deviceId: deviceId,
            cumulativeEnergyWh: cumulativeEnergyWh,
            submitter: msg.sender
        }));

        emit BatchLogged(
            msg.sender,
            logs.length - 1,
            deviceIdHash,
            merkleRoot,
            batchHash,
            timestamp,
            deviceId,
            cumulativeEnergyWh
        );
    }

    function getLog(uint256 index) public view returns (
        bytes32 merkleRoot,
        bytes32 batchHash,
        uint256 timestamp,
        bytes32 deviceIdHash,
        string memory deviceId,
        uint256 cumulativeEnergyWh,
        address submitter
    ) {
        require(index < logs.length, "Invalid index");
        LogEntry storage log = logs[index];
        return (
            log.merkleRoot,
            log.batchHash,
            log.timestamp,
            log.deviceIdHash,
            log.deviceId,
            log.cumulativeEnergyWh,
            log.submitter
        );
    }

    function getTotalLogs() public view returns (uint256) {
        return logs.length;
    }

    function getAllLogs() public view returns (LogEntry[] memory) {
        return logs;
    }
}