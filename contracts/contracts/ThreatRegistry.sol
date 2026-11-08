// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ThreatRegistry
/// @notice Tamper-evident registry of threat-report fingerprints for TrustLens.
/// @dev Stores ONLY a SHA-256 hash of each report plus its risk level. Raw URLs, messages and personal
///      data stay off-chain. A record proves a report's integrity and history — not that it is true.
///      Interface agreed in AGENTS.md §7 (the backend's registry/chain.py depends on it).
contract ThreatRegistry {
    enum Status {
        Active, // 0
        Disputed, // 1
        Revised // 2
    }

    struct Report {
        bytes32 reportHash;
        address submitter;
        uint64 timestamp;
        Status status;
        uint32 revisions;
        string riskLevel;
    }

    uint256 private _count;
    mapping(uint256 => Report) private _reports;
    mapping(uint256 => bytes32[]) private _history; // every hash a report has had, oldest first

    /// @notice Report id that a hash was registered under (0 = never registered).
    mapping(bytes32 => uint256) public idOfHash;
    /// @notice How many times each report has been disputed.
    mapping(uint256 => uint256) public disputeCount;

    event ReportSubmitted(uint256 indexed id, bytes32 reportHash, address indexed submitter, uint256 timestamp);
    event ReportRevised(uint256 indexed id, bytes32 newHash, uint256 revision);
    event ReportDisputed(uint256 indexed id, address indexed by, string reasonCode);

    error UnknownReport(uint256 id);
    error EmptyHash();
    error HashAlreadyRegistered(bytes32 reportHash, uint256 existingId);
    error InvalidText();
    error NotSubmitter();

    modifier exists(uint256 id) {
        if (id == 0 || id > _count) revert UnknownReport(id);
        _;
    }

    /// @notice Register the fingerprint of a new report. Returns its id (ids start at 1).
    function submitReport(bytes32 reportHash, string calldata riskLevel) external returns (uint256 id) {
        _checkNewHash(reportHash);
        _checkShortText(riskLevel);
        id = ++_count;
        _reports[id] = Report({
            reportHash: reportHash,
            submitter: msg.sender,
            timestamp: uint64(block.timestamp),
            status: Status.Active,
            revisions: 0,
            riskLevel: riskLevel
        });
        _history[id].push(reportHash);
        idOfHash[reportHash] = id;
        emit ReportSubmitted(id, reportHash, msg.sender, block.timestamp);
    }

    /// @notice Replace a report's hash with a corrected version. Only the original submitter may do this;
    ///         the previous hashes stay in the history.
    function reviseReport(uint256 id, bytes32 newHash) external exists(id) {
        Report storage r = _reports[id];
        if (msg.sender != r.submitter) revert NotSubmitter();
        _checkNewHash(newHash);
        r.reportHash = newHash;
        r.status = Status.Revised;
        r.revisions += 1;
        _history[id].push(newHash);
        idOfHash[newHash] = id;
        emit ReportRevised(id, newHash, r.revisions);
    }

    /// @notice Anyone can dispute a report with a short reason code such as "FALSE_POSITIVE" (no personal data).
    function disputeReport(uint256 id, string calldata reasonCode) external exists(id) {
        _checkShortText(reasonCode);
        _reports[id].status = Status.Disputed;
        disputeCount[id] += 1;
        emit ReportDisputed(id, msg.sender, reasonCode);
    }

    function getReport(uint256 id)
        external
        view
        exists(id)
        returns (
            bytes32 hash,
            address submitter,
            uint256 timestamp,
            string memory riskLevel,
            uint8 status,
            uint256 revisions
        )
    {
        Report storage r = _reports[id];
        return (r.reportHash, r.submitter, r.timestamp, r.riskLevel, uint8(r.status), r.revisions);
    }

    /// @notice All hashes this report has had, oldest first.
    function getHistory(uint256 id) external view exists(id) returns (bytes32[] memory) {
        return _history[id];
    }

    /// @notice True if `reportHash` is the CURRENT fingerprint of report `id`.
    function verify(uint256 id, bytes32 reportHash) external view exists(id) returns (bool) {
        return _reports[id].reportHash == reportHash;
    }

    function reportCount() external view returns (uint256) {
        return _count;
    }

    function _checkNewHash(bytes32 h) private view {
        if (h == bytes32(0)) revert EmptyHash();
        uint256 existing = idOfHash[h];
        if (existing != 0) revert HashAlreadyRegistered(h, existing);
    }

    function _checkShortText(string calldata s) private pure {
        uint256 n = bytes(s).length;
        if (n == 0 || n > 32) revert InvalidText();
    }
}
