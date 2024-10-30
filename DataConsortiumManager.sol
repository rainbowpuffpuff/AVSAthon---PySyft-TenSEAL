pragma solidity ^0.8.12;

// Import OpenZeppelin Contracts with specific version
import "@openzeppelin/contracts@4.8.0/access/AccessControlEnumerable.sol";
import "@openzeppelin/contracts@4.8.0/utils/structs/EnumerableSet.sol";

/**
 * @title DataConsortiumAVS
 * @dev Manages a data consortium for federated learning with homomorphic encryption using PySyft and TenSEAL terminology.
 *      Handles data owner and data scientist registration, code request submissions, approvals, and job execution tracking.
 */
contract DataConsortiumAVS is AccessControlEnumerable {
    using EnumerableSet for EnumerableSet.AddressSet;

    // Define roles using keccak256 hashes for uniqueness
    bytes32 public constant DATA_OWNER_ROLE = keccak256("DATA_OWNER_ROLE");
    bytes32 public constant DATA_SCIENTIST_ROLE = keccak256("DATA_SCIENTIST_ROLE");
    bytes32 public constant AGGREGATOR_ROLE = keccak256("AGGREGATOR_ROLE");

    // Data Owners and Data Scientists management
    EnumerableSet.AddressSet private _dataOwners;
    EnumerableSet.AddressSet private _dataScientists;

    // Mapping from Data Owner to their datasets
    mapping(address => uint256[]) private _dataOwnerDatasets;

    // Dataset structure
    struct Dataset {
        uint256 id;
        string name;
        string description;
        string dataUri; // URI to the private data (hosted securely by the Data Owner)
        string mockDataUri; // URI to the mock data for prototyping
    }

    // Mapping from dataset ID to Dataset
    mapping(uint256 => Dataset) private _datasets;
    uint256 private _nextDatasetId = 1;

    // Syft Function Request structure
    struct CodeRequest {
        uint256 id;
        address dataScientist;
        uint256 datasetId;
        string functionHash; // Hash of the Syft Function code
        string inputPolicy;
        string outputPolicy;
        string status; // "Pending", "Approved", "Denied", "Executed"
        string resultUri; // URI to the result (if approved and executed)
    }

    // Mapping from request ID to CodeRequest
    mapping(uint256 => CodeRequest) private _codeRequests;
    uint256 private _nextRequestId = 1;

    // Events
    event DataOwnerRegistered(address indexed dataOwner);
    event DataScientistRegistered(address indexed dataScientist);
    event DatasetCreated(address indexed dataOwner, uint256 datasetId);
    event CodeRequestSubmitted(uint256 indexed requestId, address indexed dataScientist, uint256 datasetId);
    event CodeRequestApproved(uint256 indexed requestId, address indexed dataOwner);
    event CodeRequestDenied(uint256 indexed requestId, address indexed dataOwner, string reason);
    event JobExecuted(uint256 indexed requestId, string resultUri);
    event AggregatorChanged(address indexed newAggregator);

    /**
     * @dev Modifier to restrict functions to only the contract deployer (admin).
     */
    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Not authorized: Admin only");
        _;
    }

    /**
     * @dev Constructor sets up the deployer as the default admin.
     */
    constructor() {
        // Grant the contract deployer the default admin role
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);

        // Initialize roles' admin roles to DEFAULT_ADMIN_ROLE
        _setRoleAdmin(DATA_OWNER_ROLE, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(DATA_SCIENTIST_ROLE, DEFAULT_ADMIN_ROLE);
        _setRoleAdmin(AGGREGATOR_ROLE, DEFAULT_ADMIN_ROLE);
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                          Data Owner Management                             //
    ////////////////////////////////////////////////////////////////////////////////

    /**
     * @dev Registers a data owner.
     *      Can only be called by the admin (deployer).
     * @param dataOwner Address of the data owner to register.
     */
    function registerDataOwner(address dataOwner) external onlyAdmin {
        require(dataOwner != address(0), "Invalid address");
        require(!_dataOwners.contains(dataOwner), "Data Owner already registered");

        _dataOwners.add(dataOwner);
        _grantRole(DATA_OWNER_ROLE, dataOwner);

        emit DataOwnerRegistered(dataOwner);
    }

    /**
     * @dev Creates a new dataset.
     *      Can only be called by a registered data owner.
     * @param name Name of the dataset.
     * @param description Description of the dataset.
     * @param dataUri URI to the private data.
     * @param mockDataUri URI to the mock data.
     * @return datasetId The ID of the newly created dataset.
     */
    function createDataset(
        string calldata name,
        string calldata description,
        string calldata dataUri,
        string calldata mockDataUri
    ) external returns (uint256 datasetId) {
        require(hasRole(DATA_OWNER_ROLE, msg.sender), "Not a registered Data Owner");
        require(bytes(name).length > 0, "Dataset name required");
        require(bytes(dataUri).length > 0, "Data URI required");
        require(bytes(mockDataUri).length > 0, "Mock Data URI required");

        datasetId = _nextDatasetId++;
        Dataset storage dataset = _datasets[datasetId];
        dataset.id = datasetId;
        dataset.name = name;
        dataset.description = description;
        dataset.dataUri = dataUri;
        dataset.mockDataUri = mockDataUri;

        _dataOwnerDatasets[msg.sender].push(datasetId);

        emit DatasetCreated(msg.sender, datasetId);
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                          Data Scientist Management                         //
    ////////////////////////////////////////////////////////////////////////////////

    /**
     * @dev Registers a data scientist.
     *      Can be called by the data scientist themselves.
     */
    function registerDataScientist() external {
        address dataScientist = msg.sender;
        require(!_dataScientists.contains(dataScientist), "Data Scientist already registered");

        _dataScientists.add(dataScientist);
        _grantRole(DATA_SCIENTIST_ROLE, dataScientist);

        emit DataScientistRegistered(dataScientist);
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                          Code Request Management                           //
    ////////////////////////////////////////////////////////////////////////////////

    /**
     * @dev Submits a code request to execute a Syft Function on a dataset.
     *      Can only be called by a registered data scientist.
     * @param datasetId ID of the dataset to access.
     * @param functionHash Hash of the Syft Function code.
     * @param inputPolicy Input policy defined in the Syft Function.
     * @param outputPolicy Output policy defined in the Syft Function.
     * @return requestId The ID of the newly created code request.
     */
    function submitCodeRequest(
        uint256 datasetId,
        string calldata functionHash,
        string calldata inputPolicy,
        string calldata outputPolicy
    ) external returns (uint256 requestId) {
        require(hasRole(DATA_SCIENTIST_ROLE, msg.sender), "Not a registered Data Scientist");
        require(_datasets[datasetId].id != 0, "Dataset does not exist");
        require(bytes(functionHash).length > 0, "Function hash required");

        requestId = _nextRequestId++;
        CodeRequest storage codeRequest = _codeRequests[requestId];
        codeRequest.id = requestId;
        codeRequest.dataScientist = msg.sender;
        codeRequest.datasetId = datasetId;
        codeRequest.functionHash = functionHash;
        codeRequest.inputPolicy = inputPolicy;
        codeRequest.outputPolicy = outputPolicy;
        codeRequest.status = "Pending";

        emit CodeRequestSubmitted(requestId, msg.sender, datasetId);
    }

    /**
     * @dev Approves a code request.
     *      Can only be called by the data owner who owns the dataset.
     * @param requestId ID of the code request to approve.
     */
    function approveCodeRequest(uint256 requestId) external {
        require(_codeRequests[requestId].id != 0, "Code request does not exist");
        CodeRequest storage codeRequest = _codeRequests[requestId];
        uint256 datasetId = codeRequest.datasetId;
        require(_datasets[datasetId].id != 0, "Dataset does not exist");
        require(hasRole(DATA_OWNER_ROLE, msg.sender), "Not a registered Data Owner");

        // Check that the data owner owns the dataset
        bool ownsDataset = false;
        uint256[] storage ownerDatasets = _dataOwnerDatasets[msg.sender];
        for (uint256 i = 0; i < ownerDatasets.length; i++) {
            if (ownerDatasets[i] == datasetId) {
                ownsDataset = true;
                break;
            }
        }
        require(ownsDataset, "Data Owner does not own the dataset");

        require(
            keccak256(bytes(codeRequest.status)) == keccak256(bytes("Pending")),
            "Code request is not pending"
        );

        codeRequest.status = "Approved";

        emit CodeRequestApproved(requestId, msg.sender);
    }

    /**
     * @dev Denies a code request.
     *      Can only be called by the data owner who owns the dataset.
     * @param requestId ID of the code request to deny.
     * @param reason Reason for denial.
     */
    function denyCodeRequest(uint256 requestId, string calldata reason) external {
        require(_codeRequests[requestId].id != 0, "Code request does not exist");
        CodeRequest storage codeRequest = _codeRequests[requestId];
        uint256 datasetId = codeRequest.datasetId;
        require(_datasets[datasetId].id != 0, "Dataset does not exist");
        require(hasRole(DATA_OWNER_ROLE, msg.sender), "Not a registered Data Owner");

        // Check that the data owner owns the dataset
        bool ownsDataset = false;
        uint256[] storage ownerDatasets = _dataOwnerDatasets[msg.sender];
        for (uint256 i = 0; i < ownerDatasets.length; i++) {
            if (ownerDatasets[i] == datasetId) {
                ownsDataset = true;
                break;
            }
        }
        require(ownsDataset, "Data Owner does not own the dataset");

        require(
            keccak256(bytes(codeRequest.status)) == keccak256(bytes("Pending")),
            "Code request is not pending"
        );

        codeRequest.status = "Denied";

        emit CodeRequestDenied(requestId, msg.sender, reason);
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                          Job Execution Management                          //
    ////////////////////////////////////////////////////////////////////////////////

    /**
     * @dev Marks a code request as executed and provides the result URI.
     *      Can only be called by the data owner who owns the dataset or an aggregator.
     * @param requestId ID of the code request.
     * @param resultUri URI to the result of the execution.
     */
    function markJobExecuted(uint256 requestId, string calldata resultUri) external {
        require(_codeRequests[requestId].id != 0, "Code request does not exist");
        CodeRequest storage codeRequest = _codeRequests[requestId];
        uint256 datasetId = codeRequest.datasetId;
        require(_datasets[datasetId].id != 0, "Dataset does not exist");

        bool authorized = false;

        // Check if sender is the data owner
        if (hasRole(DATA_OWNER_ROLE, msg.sender)) {
            // Check that the data owner owns the dataset
            uint256[] storage ownerDatasets = _dataOwnerDatasets[msg.sender];
            for (uint256 i = 0; i < ownerDatasets.length; i++) {
                if (ownerDatasets[i] == datasetId) {
                    authorized = true;
                    break;
                }
            }
        }

        // Check if sender is the aggregator
        if (!authorized && hasRole(AGGREGATOR_ROLE, msg.sender)) {
            authorized = true;
        }

        require(authorized, "Not authorized to mark job as executed");

        require(
            keccak256(bytes(codeRequest.status)) == keccak256(bytes("Approved")),
            "Code request is not approved"
        );

        codeRequest.status = "Executed";
        codeRequest.resultUri = resultUri;

        emit JobExecuted(requestId, resultUri);
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                              Role Management                               //
    ////////////////////////////////////////////////////////////////////////////////

    /**
     * @dev Assigns the aggregator role to a new address.
     *      Can only be called by the admin (deployer).
     *      Revokes the role from all existing holders before granting it to the new address.
     * @param newAggregator Address of the new aggregator.
     */
    function setAggregator(address newAggregator) external onlyAdmin {
        require(newAggregator != address(0), "Invalid address");

        // Revoke aggregator role from all current holders
        uint256 count = getRoleMemberCount(AGGREGATOR_ROLE);
        for (uint256 i = count; i > 0; i--) {
            address currentAggregator = getRoleMember(AGGREGATOR_ROLE, i - 1);
            _revokeRole(AGGREGATOR_ROLE, currentAggregator);
        }

        // Grant aggregator role to the new aggregator
        _grantRole(AGGREGATOR_ROLE, newAggregator);
        emit AggregatorChanged(newAggregator);
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                               View Functions                               //
    ////////////////////////////////////////////////////////////////////////////////

    /**
     * @dev Retrieves a dataset by ID.
     * @param datasetId ID of the dataset.
     * @return Dataset structure.
     */
    function getDataset(uint256 datasetId) external view returns (Dataset memory) {
        require(_datasets[datasetId].id != 0, "Dataset does not exist");
        return _datasets[datasetId];
    }

    /**
     * @dev Retrieves datasets owned by a data owner.
     * @param dataOwner Address of the data owner.
     * @return Array of dataset IDs.
     */
    function getDatasetsByOwner(address dataOwner) external view returns (uint256[] memory) {
        require(hasRole(DATA_OWNER_ROLE, dataOwner), "Not a registered Data Owner");
        return _dataOwnerDatasets[dataOwner];
    }

    /**
     * @dev Retrieves a code request by ID.
     * @param requestId ID of the code request.
     * @return CodeRequest structure.
     */
    function getCodeRequest(uint256 requestId) external view returns (CodeRequest memory) {
        require(_codeRequests[requestId].id != 0, "Code request does not exist");
        return _codeRequests[requestId];
    }

    /**
     * @dev Retrieves code requests submitted by a data scientist.
     * @param dataScientist Address of the data scientist.
     * @return Array of CodeRequest structures.
     */
    function getCodeRequestsByDataScientist(address dataScientist) external view returns (CodeRequest[] memory) {
        require(hasRole(DATA_SCIENTIST_ROLE, dataScientist), "Not a registered Data Scientist");

        uint256 totalRequests = _nextRequestId - 1;
        uint256 count = 0;

        // First, count the number of requests by the data scientist
        for (uint256 i = 1; i <= totalRequests; i++) {
            if (_codeRequests[i].dataScientist == dataScientist) {
                count++;
            }
        }

        // Then, collect them into an array
        CodeRequest[] memory requests = new CodeRequest[](count);
        uint256 index = 0;
        for (uint256 i = 1; i <= totalRequests; i++) {
            if (_codeRequests[i].dataScientist == dataScientist) {
                requests[index] = _codeRequests[i];
                index++;
            }
        }

        return requests;
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                            Fallback Functions                              //
    ////////////////////////////////////////////////////////////////////////////////

    // The contract does not accept Ether, so we disable the fallback functions.

    receive() external payable {
        revert("Contract does not accept Ether");
    }

    fallback() external payable {
        revert("Contract does not accept Ether");
    }
}
    
