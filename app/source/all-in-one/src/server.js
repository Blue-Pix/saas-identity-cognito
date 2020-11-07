'use strict';

const express = require('express');
const bodyParser = require('body-parser');
const uuidV4 = require('uuid/v4');
const request = require('request');
const async = require('async');
const AWS = require('aws-sdk');
const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
const CognitoUserPool = AmazonCognitoIdentity.CognitoUserPool;

const configModule = require('../shared-modules/config-helper/config.js');
var configuration = configModule.configure(process.env.NODE_ENV);

const winston = require('winston');
winston.level = configuration.loglevel;

const tenantURL = "http://localhost:" + configuration.port.all + "/tenant";
const userURL   = "http://localhost:" + configuration.port.all + "/user";

const tokenManager = require('../shared-modules/token-manager/token-manager.js');
const DynamoDBHelper = require('../shared-modules/dynamodb-helper/dynamodb-helper.js');
const DBHelper = require('../shared-modules/db-helper/db-helper.js');
const dbHelper = new DBHelper();
const cognitoUsers = require('./cognito-user.js');

AWS.config.update({region: configuration.aws_region});

var app = express();
var bearerToken = '';
var tenantId = '';

var tenantSchema = {
    TableName : configuration.table.tenant,
    KeySchema: [
        { AttributeName: "id", KeyType: "HASH"}  //Partition key
    ],
    AttributeDefinitions: [
        { AttributeName: "id", AttributeType: "S" }
    ],
    ProvisionedThroughput: {
        ReadCapacityUnits: 10,
        WriteCapacityUnits: 10
    }
};

var productSchema = {
    TableName : configuration.table.product,
    KeySchema: [
        { AttributeName: "tenantId", KeyType: "HASH"},  //Partition key
        { AttributeName: "productId", KeyType: "RANGE" }  //Sort key
    ],
    AttributeDefinitions: [
        { AttributeName: "tenantId", AttributeType: "S" },
        { AttributeName: "productId", AttributeType: "S" }
    ],
    ProvisionedThroughput: {
        ReadCapacityUnits: 10,
        WriteCapacityUnits: 10
    }
};

var userSchema = {
    TableName : configuration.table.user,
    KeySchema: [
        { AttributeName: "tenant_id", KeyType: "HASH"},  //Partition key
        { AttributeName: "id", KeyType: "RANGE" }  //Sort key
    ],
    AttributeDefinitions: [
        { AttributeName: "tenant_id", AttributeType: "S" },
        { AttributeName: "id", AttributeType: "S" }
    ],
    ProvisionedThroughput: {
        ReadCapacityUnits: 10,
        WriteCapacityUnits: 10
    },
    GlobalSecondaryIndexes: [
        {
            IndexName: 'UserNameIndex',
            KeySchema: [
                { AttributeName: "id", KeyType: "HASH"}
            ],
            Projection: {
                ProjectionType: 'ALL'
            },
            ProvisionedThroughput: {
                ReadCapacityUnits: 10,
                WriteCapacityUnits: 10
            }
        }
    ]
};

// Configure middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: false
}));

app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, PATCH, DELETE");
    res.header("Access-Control-Allow-Headers", "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With, Origin, X-Amz-Date, Authorization, X-Api-Key, X-Amz-Security-Token, Access-Control-Allow-Origin");
    bearerToken = req.get('Authorization');
    if ('OPTIONS' == req.method) {
        res.send(200);
    }
    else {
        if (bearerToken) {
            tenantId = tokenManager.getTenantId(req);
        }
        next();
    }
});

app.get('/health', function(req, res) {
    res.status(200).send({service: 'All-in-one', isAlive: true});
});

// FROM HERE: auth service
// process login request
app.post('/auth', function (req, res) {
    var user = req.body;

    tokenManager.getUserPool(user.userName, function (error, userPoolLookup) {
        if (!error) {
            // get the pool data from the response
            var poolData = {
                UserPoolId: userPoolLookup.userPoolId,
                ClientId: userPoolLookup.client_id
            };
            // construct a user pool object
            var userPool = new CognitoUserPool(poolData);
            // configure the authentication credentials
            var authenticationData = {
                Username: user.userName,
                Password: user.password
            };
            // create object with user/pool combined
            var userData = {
                Username: user.userName,
                Pool: userPool
            };
            // init Cognito auth details with auth data
            var authenticationDetails = new AWS.CognitoIdentityServiceProvider.AuthenticationDetails(authenticationData);
            // authenticate user to in Cognito user pool
            var cognitoUser = new AWS.CognitoIdentityServiceProvider.CognitoUser(userData);

            cognitoUser.authenticateUser(authenticationDetails, {
                onSuccess: function (result) {
                    // get the ID token
                    var idToken = result.getIdToken().getJwtToken();
                    var AccessToken = result.getAccessToken().getJwtToken();
                    res.json({token: idToken, access: AccessToken});
                },
                onFailure: function(err) {
                    if (res.status != 400) {
                        res.json(err);
                        return;
                    }
                },
                mfaRequired: function(codeDeliveryDetails) {
                    // MFA is required to complete user authentication.
                    // Get the code from user and call

                    //MFA is Disabled for this QuickStart. This may be submitted as an enhancement, if their are sufficient requests.
                    var mfaCode = '';

                    if (user.mfaCode == undefined){
                        res.status(200);
                        res.json({mfaRequired: true});
                        return;
                    }
                    cognitoUser.sendMFACode(mfaCode, this)

                },
                newPasswordRequired: function(userAttributes, requiredAttributes) {
                    // User was signed up by an admin and must provide new
                    // password and required attributes, if any, to complete
                    // authentication.
                    if (user.newPassword == undefined){
                        res.status(200);
                        res.json({newPasswordRequired: true});
                        return;
                    }
                    // These attributes are not mutable and should be removed from map.
                    delete userAttributes.email_verified;
                    delete userAttributes['custom:tenant_id'];
                    cognitoUser.completeNewPasswordChallenge(user.newPassword, userAttributes, this);
                }
            });
        }
        else {
            winston.error("Error Authenticating User: ", error);
            res.status(404);
            res.json(error);
        }
    }, userURL);
});

// FROM HERE: reg service
app.post('/reg', function (req, res) {
    var tenant = req.body;

    // Generate the tenant id
    tenant.id = 'TENANT' + uuidV4();
    winston.debug('Creating Tenant ID: ' + tenant.id);
    tenant.id = tenant.id.split('-').join('');

    // if the tenant doesn't exist, create one
    tenantExists(tenant, function(tenantExists) {
        if (tenantExists) {
            winston.error("Error registering new tenant");
            res.status(400).send("Error registering new tenant");
        }
        else {
            registerTenantAdmin(tenant)
                .then(function (tenData) {
                    //Adding Data to the Tenant Object that will be required to cleaning up all created resources for all tenants.
                    tenant.UserPoolId = tenData.pool.UserPool.Id;
                    tenant.IdentityPoolId = tenData.identityPool.IdentityPoolId;

                    tenant.systemAdminRole = tenData.role.systemAdminRole;
                    tenant.systemSupportRole = tenData.role.systemSupportRole;
                    tenant.trustRole = tenData.role.trustRole;

                    tenant.systemAdminPolicy = tenData.policy.systemAdminPolicy;
                    tenant.systemSupportPolicy = tenData.policy.systemSupportPolicy;

                    tenant.ClientId = tenData.userPoolClient.UserPoolClient.ClientId;

                    saveTenantData(tenant)
                })
                .then(function () {
                    winston.debug("Tenant registered: " + tenant.id);
                    res.status(200).send("Tenant " + tenant.id + " registered");
                })
                .catch(function (error) {
                    winston.error("Error registering new tenant: " + error.message);
                    res.status(400).send("Error registering tenant: " + error.message);
                });
        }
    });
});

/**
 * Determine if a tenant can be created (they may already exist)
 * @param tenant The tenant data
 * @returns True if the tenant exists
 */
function tenantExists(tenant, callback) {
    // Create URL for user-manager request
    var userExistsUrl = userURL + '/pool/' + tenant.userName;

    // see if the user already exists
    request({
        url: userExistsUrl,
        method: "GET",
        json: true,
        headers: {"content-type": "application/json"}
    }, function (error, response, body) {
        if (error)
            callback(false);
        else if ((response != null) && (response.statusCode == 400))
            callback(false);
        else {
            if (body.userName === tenant.userName)
                callback(true);
            else
                callback(false);
        }
    });
};

/**
 * Register a new tenant user and provision policies for that user
 * @param tenant The new tenant data
 * @returns {Promise} Results of tenant provisioning
 */
function registerTenantAdmin(tenant) {
    var promise = new Promise(function(resolve, reject) {

        // init the request with tenant data
        var tenantAdminData = {
            "tenant_id": tenant.id,
            "companyName": tenant.companyName,
            // "accountName": tenant.accountName,
            // "ownerName": tenant.ownerName,
            "tier": tenant.tier,
            "email": tenant.email,
            "userName": tenant.userName,
            "role": tenant.role,
            "firstName": tenant.firstName,
            "lastName": tenant.lastName
        };

        // REST API URL
        var registerTenantUserURL = userURL + '/reg';
        // fire request
        request({
            url: registerTenantUserURL,
            method: "POST",
            json: true,
            headers: {"content-type": "application/json"},
            body: tenantAdminData
        }, function (error, response, body) {
            if (error || (response.statusCode != 200))
                reject(error)
            else {
                resolve(body);
            }
        });
    });

    return promise;
}

/**
 * Save the configration and status of the new tenant
 * @param tenant Data for the tenant to be created
 * @returns {Promise} The created tenant
 */
function saveTenantData(tenant) {
    var promise = new Promise(function(resolve, reject) {
        // init the tenant sace request
        var tenantRequestData = {
            "id": tenant.id,
            "companyName": tenant.companyName,
            "tier": tenant.tier,
            "email": tenant.email,
            "status": "Active",
            "UserPoolId": tenant.UserPoolId,
            "IdentityPoolId": tenant.IdentityPoolId,
            "ClientId": tenant.ClientId,
            "systemAdminRole": tenant.systemAdminRole,
            "systemSupportRole": tenant.systemSupportRole,
            "trustRole": tenant.trustRole,
            "systemAdminPolicy": tenant.systemAdminPolicy,
            "systemSupportPolicy": tenant.systemSupportPolicy,
            "userName": tenant.userName,
        };

        // fire request
        request({
            url: tenantURL,
            method: "POST",
            json: true,
            headers: {"content-type": "application/json"},
            body: tenantRequestData
        }, function (error, response, body) {
            if (error || (response.statusCode != 200))
                reject(error);
            else
                resolve(body);
        });
    });

    return promise;
}

// FROM HERE: tenant service
// Create REST entry points
app.get('/tenant/:id', function (req, res) {
    winston.debug('Fetching tenant: ' + req.params.id);

    // init params structure with request params
    var tenantIdParam = {
        id: req.params.id
    }

    tokenManager.getCredentialsFromToken(req, function(credentials) {
        // construct the helper object
        var dynamoHelper = new DynamoDBHelper(tenantSchema, credentials, configuration);

        dynamoHelper.getItem(tenantIdParam, credentials, function (err, tenant) {
            if (err) {
                winston.error('Error getting tenant: ' + err.message);
                res.status(400).send('{"Error" : "Error getting tenant"}');
            }
            else {
                winston.debug('Tenant ' + req.params.id + ' retrieved');
                res.status(200).send(tenant);
            }
        });
    });
});

app.get('/tenants', function(req, res) {
    winston.debug('Fetching all tenants');
    
    var authToken = tokenManager.getRequestAuthToken(req);
    var decodedToken = tokenManager.decodeToken(authToken);
    var tenantId = decodedToken['custom:tenant_id'];

    tokenManager.getCredentialsFromToken(req, function(credentials) {
        var scanParams = {
            TableName: tenantSchema.TableName,
        }

        // construct the helper object
        var dynamoHelper = new DynamoDBHelper(tenantSchema, credentials, configuration);

        dynamoHelper.scan(scanParams, credentials, function (error, tenants) {
            if (error) {
                winston.error('Error retrieving tenants: ' + error.message);
                res.status(400).send('{"Error" : "Error retrieving tenants"}');
            }
            else {
                winston.debug('Tenants successfully retrieved');
                res.status(200).send(tenants);
            }

        });
    });
});

app.get('/tenants/system', function(req, res) {
    winston.debug('Fetching all tenants required to clean up infrastructure');
//Note: Reference Architecture not leveraging Client Certificate to secure system only endpoints. Please integrate the following endpoint with a Client Certificate.
    var credentials = {};
    tokenManager.getSystemCredentials(function (systemCredentials) {
        credentials = systemCredentials;
        var scanParams = {
            TableName: tenantSchema.TableName,
        }

        // construct the helper object
        var dynamoHelper = new DynamoDBHelper(tenantSchema, credentials, configuration);

        dynamoHelper.scan(scanParams, credentials, function (error, tenants) {
            if (error) {
                winston.error('Error retrieving tenants: ' + error.message);
                res.status(400).send('{"Error" : "Error retrieving tenants"}');
            }
            else {
                winston.debug('Tenants successfully retrieved');
                res.status(200).send(tenants);
            }

        });
    });
});

app.post('/tenant', function(req, res) {
    var credentials = {};
    tokenManager.getSystemCredentials(function (systemCredentials) {
        credentials = systemCredentials;
        var tenant = req.body;
        winston.debug('Creating Tenant: ' + tenant.id);

        // construct the helper object
        var dynamoHelper = new DynamoDBHelper(tenantSchema, credentials, configuration);

        dynamoHelper.putItem(tenant, credentials, function (err, tenant) {
            if (err) {
                winston.error('Error creating new tenant: ' + err.message);
                res.status(400).send('{"Error" : "Error creating tenant"}');
            }
            else {
                winston.debug('Tenant ' + tenant.id + ' created');
                res.status(200).send({status: 'success'});
            }
        });
    })
});

//add code to add disable flag to tenant
// app.post('/disable', function(req, res) {
//     var tenant = new Tenant(req.body);
//     winston.debug('Disable Tenant: ' + tenant.id);
//     tenant.save(function(err) {
//         if (err) {
//             winston.error('Error creating new tenant: ' + err.message);
//             res.status(400);
//             res.json(err);
//         }
//         else {
//             winston.error('tenant' + tenant.id + 'created');
//             res.json(tenant);
//         }

//     });
// });

app.put('/tenant', function(req, res) {
    winston.debug('Updating tenant: ' + req.body.id);
    tokenManager.getCredentialsFromToken(req, function(credentials) {
        // init the params from the request data
        var keyParams = {
            id: req.body.id
        }

        var tenantUpdateParams = {
            TableName: tenantSchema.TableName,
            Key: keyParams,
            UpdateExpression: "set " +
                "companyName=:companyName, " +
                "tier=:tier, " +
                "#status=:status",
            ExpressionAttributeNames: {
                '#status' : 'status'
            },
            ExpressionAttributeValues: {
                ":companyName": req.body.companyName,
                ":tier":req.body.tier,
                ":status":req.body.status
            },
            ReturnValues:"UPDATED_NEW"
        };

        // construct the helper object
        var dynamoHelper = new DynamoDBHelper(tenantSchema, credentials, configuration);

        dynamoHelper.updateItem(tenantUpdateParams, credentials, function (err, tenant) {
            if (err) {
                winston.error('Error updating tenant: ' + err.message);
                res.status(400).send('{"Error" : "Error updating tenant"}');
            }
            else {
                winston.debug('Tenant ' + req.body.title + ' updated');
                res.status(200).send(tenant);
            }
        });
    });
});

app.delete('/tenant/:id', function(req, res) {
    winston.debug('Deleting Tenant: ' + req.params.id);

    tokenManager.getCredentialsFromToken(req, function(credentials) {
        // init parameter structure
        var deleteTenantParams = {
            TableName : tenantSchema.TableName,
            Key: {
                id: req.params.id
            }
        };

        // construct the helper object
        var dynamoHelper = new DynamoDBHelper(tenantSchema, credentials, configuration);

        dynamoHelper.deleteItem(deleteTenantParams, credentials, function (err, product) {
            if (err) {
                winston.error('Error deleting tenant: ' + err.message);
                res.status(400).send('{"Error" : "Error deleting tenant"}');
            }
            else {
                winston.debug('Tenant ' + req.params.id + ' deleted');
                res.status(200).send({status: 'success'});
            }
        });
    });
});

// FROM HERE: user service
/**
 * WARNING: THIS WILL REMOVE THE DYNAMODB TABLES FOR THIS QUICKSTART.
 * NOTE: In production, it is recommendended to have a backup of all Tables, and only manage these tables from corresponding micro-services.
 * Delete DynamoDB Tables required for the Infrastructure including the User, Tenant, Product, and Order Tables.
 */
app.delete('/user/tables', function (req, res) {

        // Delete User Table
        cognitoUsers.deleteTable(configuration.table.user)
            .then(function(response) {
            })
            .catch(function(err) {
                res.status(400).send("Error deleting " + configuration.table.user + err.message);
            });
        // Delete Tenant Table
        cognitoUsers.deleteTable(configuration.table.tenant)
            .then(function(response) {
            })
            .catch(function(err) {
                res.status(400).send("Error deleting " + configuration.table.tenant + err.message);
            });
        // Delete Product Table
        cognitoUsers.deleteTable(configuration.table.product)
            .then(function(response) {
            })
            .catch(function(err) {
                res.status(400).send("Error deleting " + configuration.table.product + err.message);
            });
        // Delete Order Table
        cognitoUsers.deleteTable(configuration.table.order)
            .then(function(response) {
            })
            .catch(function(err) {
                res.status(400).send("Error deleting " + configuration.table.order + err.message);
            });

            res.status(200).send('Initiated removal of DynamoDB Tables');

});


/**
 * WARNING: THIS WILL REMOVE ALL THE COGNITO USER POOLS, IDENTITY POOLS, ROLES, AND POLICIES CREATED BY THIS QUICKSTART.
 * Delete Infrastructure Created by Multi-tenant Identity Reference Architecture
 */
app.delete('/user/tenants', function (req, res) {
    winston.debug('Cleaning up Identity Reference Architecture: ');

    var input = {};
    tokenManager.getInfra(input, function (error, response, tenantURL) {
        // handle error first, so one less indentation later
        if (error) {
            res.status(400).send(error);
            return;
        }
        else {
        var infra = response;
        var items = Object.keys(infra).length;
        winston.debug(items + ' Tenants with Infrastructure');
        winston.debug('-------------------------------------');
        var pool = "";
        var i;
        // process each item in series
        async.eachSeries(infra, function (item, callback) {
            // execute your logic
            pool += item;

            // in this case item is infra[i] in the original code
            var UserPoolId = item.UserPoolId;
            var IdentityPoolId = item.IdentityPoolId;
            var systemAdminRole = item.systemAdminRole;
            var systemSupportRole = item.systemSupportRole;
            var trustRole = item.trustRole;
            var systemAdminPolicy = item.systemAdminPolicy;
            var systemSupportPolicy = item.systemSupportPolicy;

            // delete user pool
            cognitoUsers.deleteUserPool(UserPoolId)
                .then(function (userPoolData) {
                    //delete identity pool
                    return cognitoUsers.deleteIdentityPool(IdentityPoolId);
                })
                .then(function (identityPoolData) {
                    //delete role
                    return cognitoUsers.detachRolePolicy(systemAdminPolicy, systemAdminRole);
                })
                .then(function (detachSystemRolePolicyData) {
                    //delete role
                    return cognitoUsers.detachRolePolicy(systemSupportPolicy, systemSupportRole);
                })
                .then(function (detachSupportRolePolicyData) {
                    //delete role
                    return cognitoUsers.deletePolicy(systemAdminPolicy);
                })
                .then(function (systemAdminPolicyData) {
                    //delete role
                    return cognitoUsers.deletePolicy(systemSupportPolicy);
                })
                .then(function (systemSupportPolicyData) {
                    //delete role
                    return cognitoUsers.deleteRole(systemAdminRole);
                })
                .then(function (systemAdminRoleData) {
                    //delete role
                    return cognitoUsers.deleteRole(systemSupportRole);
                })
                .then(function (systemSupportRoleData) {
                    //delete role
                    return cognitoUsers.deleteRole(trustRole);
                })
                .then(function () {
                    // promises over, return callback without errors
                    callback();
                    return;
                })
                .catch(function (err) {
                    // we caught an error, return it back to async.
                    callback(err);
                    return;
                });
        }, function (err) {
            // if err is not nil, return 400
            if (err) {
                winston.debug(err)
                res.status(400).send(err);
                return;
            }
            res.status(200).send('Success');
        });
    }
    });
});

/**
 * Lookup user pool for any user - no user data returned
 */
app.get('/user/pool/:id', function (req, res) {
    winston.debug('Looking up user pool data for: ' + req.params.id);
    tokenManager.getSystemCredentials(function (credentials) {
        lookupUserPoolData(credentials, req.params.id, null, true, function (err, user) {
            if (err) {
                res.status(400).send('{"Error" : "Error getting user"}');
            }
            else {
                if (user.length == 0)
                    res.status(400).send('{"Error": "User not found"}');
                else
                    res.status(200).send(user);
            }
        });
    });
});

/**
 * Get user attributes
 */
app.get('/user/:id', function (req, res) {
    winston.debug('Getting user id: ' + req.params.id);
    tokenManager.getCredentialsFromToken(req, function (credentials) {
        // get the tenant id from the request
        var tenantId = tokenManager.getTenantId(req);

        lookupUserPoolData(credentials, req.params.id, tenantId, false, function(err, user) {
            if (err)
                res.status(400).send('{"Error" : "Error getting user"}');
            else {
                cognitoUsers.getCognitoUser(credentials, user, function (err, user) {
                    if (err) {
                        res.status(400);
                        res.json('Error lookup user user: ' + req.params.id);
                    }
                    else {
                        res.json(user);
                    }
                })
            }
        });
    });
});

/**
 * Get a list of users using a tenant id to scope the list
 */
app.get('/users', function (req, res) {
    tokenManager.getCredentialsFromToken(req, function (credentials) {
        var userPoolId = getUserPoolIdFromRequest(req);
        cognitoUsers.getUsersFromPool(credentials, userPoolId, configuration.aws_region)
            .then(function (userList) {
                res.status(200).send(userList);
            })
            .catch(function(error) {
                res.status(400).send("Error retrieving user list: " + error.message);
            });
    }, userURL)
});

/**
 * Create a new user
 */
app.post('/user', function (req, res) {
    tokenManager.getCredentialsFromToken(req, function (credentials) {
        var user = req.body;
        winston.debug('Creating user: ' + user.userName);

        // extract requesting user and role from the token
        var authToken = tokenManager.getRequestAuthToken(req);
        var decodedToken = tokenManager.decodeToken(authToken);
        var requestingUser = decodedToken.email;
        user.tier = decodedToken['custom:tier'];
        user.tenant_id = decodedToken['custom:tenant_id'];

        // get the user pool data using the requesting user
        // all users added in the context of this user
        lookupUserPoolData(credentials, requestingUser, user.tenant_id, false, function(err, userPoolData) {
            // if the user pool found, proceed
            if (!err) {
                createNewUser(credentials, userPoolData.UserPoolId, userPoolData.IdentityPoolId, userPoolData.client_id, user.tenant_id, user)
                    .then(function(createdUser) {
                        winston.debug('User ' + user.userName + ' created');
                        res.status(200).send({status: 'success'});
                    })
                    .catch(function(err) {
                        winston.error('Error creating new user in DynamoDB: ' + err.message);
                        res.status(400).send('{"Error" : "Error creating user in DynamoDB"}');
                    });
            }
            else {
                res.status(400).send('{"Error" : "User pool not found"}');
            }
        });
    });
});

/**
 * Provision a new system admin user
 */
app.post('/user/system', function (req, res) {
    var user = req.body;
    user.tier = configuration.tier.system;
    user.role = configuration.userRole.systemAdmin;
    // get the credentials for the system user
    var credentials = {};
    tokenManager.getSystemCredentials(function (systemCredentials) {
        if(systemCredentials) {
            credentials = systemCredentials;
            // provision the tenant admin and roles
            provisionAdminUserWithRoles(user, credentials, configuration.userRole.systemAdmin, configuration.userRole.systemUser,
                function (err, result) {
                    if (err) {
                        res.status(400).send("Error provisioning system admin user");
                    }
                    else {
                        res.status(200).send(result);
                    }
                });
        }
        else{
            winston.debug("Error Obtaining System Credentials");
        }
    });
});

/**
 * Provision a new tenant admin user
 */
app.post('/user/reg', function (req, res) {
    var user = req.body;

    // get the credentials for the system user
    var credentials = {};
    tokenManager.getSystemCredentials(function (systemCredentials) {
        credentials = systemCredentials;

        // provision the tenant admin and roles
        provisionAdminUserWithRoles(user, credentials, configuration.userRole.tenantAdmin, configuration.userRole.tenantUser,
            function(err, result) {
                if (err)
                {
                    res.status(400).send("Error provisioning tenant admin user");
                }
                else
                    res.status(200).send(result);
            });
    });
});

/**
 * Enable a user that is currently disabled
 */
app.put('/user/enable', function (req, res) {
    updateUserEnabledStatus(req, true, function(err, result) {
        if (err)
            res.status(400).send('Error enabling user');
        else
            res.status(200).send(result);
    });
});


/**
 * Disable a user that is currently enabled
 */
app.put('/user/disable', function (req, res) {
    updateUserEnabledStatus(req, false, function(err, result) {
        if (err)
            res.status(400).send('Error disabling user');
        else
            res.status(200).send(result);
    });
});

/**
 * Update a user's attributes
 */
app.put('/user', function (req, res) {
    var user = req.body;
    tokenManager.getCredentialsFromToken(req, function(credentials) {
        // get the user pool id from the request
        var userPoolId = getUserPoolIdFromRequest(req);

        // update user data
        cognitoUsers.updateUser(credentials, user, userPoolId, configuration.aws_region)
            .then(function(updatedUser) {
                res.status(200).send(updatedUser);
            })
            .catch(function(err) {
                res.status(400).send("Error updating user: " + err.message);
            });
    });
});

/**
 * Delete a user
 */
app.delete('/user/:id', function (req, res) {
    var userName = req.params.id;
    tokenManager.getCredentialsFromToken(req, function (credentials) {
        winston.debug('Deleting user: ' + userName);

        // get the tenant id from the request
        var tenantId = tokenManager.getTenantId(req);

        // see if the user exists in the system
        lookupUserPoolData(credentials, userName, tenantId, false, function (err, userPoolData) {
            var userPool = userPoolData;
            // if the user pool found, proceed
            if (err) {
                res.status(400).send("User does not exist");
            }
            else {

                // first delete the user from Cognito
                cognitoUsers.deleteUser(credentials, userName, userPool.UserPoolId, configuration.aws_region)
                    .then(function (result) {
                        winston.debug('User ' + userName + ' deleted from Cognito');

                        // now delete the user from the user data base
                        var deleteUserParams = {
                            TableName: userSchema.TableName,
                            Key: {
                                id: userName,
                                tenant_id: tenantId
                            }
                        };

                        // construct the helper object
                        var dynamoHelper = new DynamoDBHelper(userSchema, credentials, configuration);

                        // delete the user from DynamoDB
                        dynamoHelper.deleteItem(deleteUserParams, credentials, function (err, user) {
                            if (err) {
                                winston.error('Error deleting DynamoDB user: ' + err.message);
                                res.status(400).send('{"Error" : "Error deleting DynamoDB user"}');
                            }
                            else {
                                winston.debug('User ' + userName + ' deleted from DynamoDB');
                                res.status(200).send({status: 'success'});
                            }
                        })
                    })
                    .catch(function (error) {
                        winston.error('Error deleting Cognito user: ' + err.message);
                        res.status(400).send('{"Error" : "Error deleting user"}');
                    });
            }
        });
    });
});

/**
 * Provision an admin user and the associated policies/roles
 * @param user The user being created
 * @param credentials Credentials to use for provisioning
 * @param adminPolicyName The name of of the admin policy to provisioned
 * @param userPolicyName The name of the user policy to be provisioned
 * @param callback Returns an object with the results of the provisioned items
 */
function provisionAdminUserWithRoles(user, credentials, adminPolicyName, userPolicyName, callback) {
    // vars that are used across multiple calls
    var createdUserPoolData = {};
    var trustPolicyTemplate = {};
    var createdTrustPolicyRole = {};
    var createdUserPoolClient = {};
    var createdIdentityPool = {};
    var createdAdminPolicy = {};
    var createdAdminRole = {};
    var createdUserPolicy = {};
    var createdUserRole = {};

    // setup params for template generation
    var policyCreationParams = {
        tenantId: user.tenant_id,
        accountId: configuration.aws_account,
        region: configuration.aws_region,
        tenantTableName: configuration.table.tenant,
        userTableName: configuration.table.user,
        productTableName: configuration.table.product,
        orderTableName: configuration.table.order
    };

    // init role based on admin policy name
    user.role = adminPolicyName;

    // see if this user is already in the system
    lookupUserPoolData(credentials, user.userName, user.tenant_id, true, function(err, userPoolData) {
        if (!err){
            callback( new Error ('{"Error" : "User already exists"}'));
            winston.debug('{"Error" : "User already exists"}');
        }
        else {
            // create the new user
            cognitoUsers.createUserPool(user.tenant_id)
                .then(function (poolData) {
                    createdUserPoolData = poolData;

                    var clientConfigParams = {
                        "ClientName": createdUserPoolData.UserPool.Name,
                        "UserPoolId": createdUserPoolData.UserPool.Id
                    };

                    // add the user pool to the policy template configuration (couldn't add until here)
                    policyCreationParams.userPoolId = createdUserPoolData.UserPool.Id;

                    // crete the user pool for the new tenant
                    return cognitoUsers.createUserPoolClient(clientConfigParams);
                })
                .then(function(userPoolClientData) {
                    createdUserPoolClient = userPoolClientData;
                    var identityPoolConfigParams = {
                        "ClientId": userPoolClientData.UserPoolClient.ClientId,
                        "UserPoolId": userPoolClientData.UserPoolClient.UserPoolId,
                        "Name": userPoolClientData.UserPoolClient.ClientName
                    };
                    return cognitoUsers.createIdentityPool(identityPoolConfigParams);
                })
                .then(function(identityPoolData) {
                    createdIdentityPool = identityPoolData;

                    // create and populate policy templates
                    trustPolicyTemplate = cognitoUsers.getTrustPolicy(identityPoolData.IdentityPoolId);

                    // get the admin policy template
                    var adminPolicyTemplate = cognitoUsers.getPolicyTemplate(adminPolicyName, policyCreationParams);

                    // setup policy name
                    var policyName = user.tenant_id + '-' + adminPolicyName + 'Policy';

                    // configure params for policy provisioning calls
                    var adminPolicyParams = {
                        "policyName": policyName,
                        "policyDocument": adminPolicyTemplate
                    };

                    return cognitoUsers.createPolicy(adminPolicyParams)
                })
                .then(function (adminPolicy) {
                    createdAdminPolicy = adminPolicy;
                    return createNewUser(credentials, createdUserPoolData.UserPool.Id, createdIdentityPool.IdentityPoolId, createdUserPoolClient.UserPoolClient.ClientId, user.tenant_id, user);
                })
                .then(function() {
                    // get the admin policy template
                    var userPolicyTemplate = cognitoUsers.getPolicyTemplate(userPolicyName, policyCreationParams);

                    // setup policy name
                    var policyName = user.tenant_id + '-' + userPolicyName + 'Policy';

                    // configure params for policy provisioning calls
                    var userPolicyParams = {
                        "policyName": policyName,
                        "policyDocument": userPolicyTemplate
                    };

                    return cognitoUsers.createPolicy(userPolicyParams)
                })
                .then(function(userPolicy) {
                    createdUserPolicy = userPolicy;

                    var adminRoleName = user.tenant_id + '-' + adminPolicyName;
                    var adminRoleParams = {
                        "policyDocument": trustPolicyTemplate,
                        "roleName": adminRoleName
                    };

                    return cognitoUsers.createRole(adminRoleParams);
                })
                .then(function(adminRole) {
                    createdAdminRole = adminRole;

                    var userRoleName = user.tenant_id + '-' + userPolicyName;
                    var userRoleParams = {
                        "policyDocument": trustPolicyTemplate,
                        "roleName": userRoleName
                    };

                    return cognitoUsers.createRole(userRoleParams)
                })
                .then(function(userRole) {
                    createdUserRole = userRole;
                    var trustPolicyRoleName = user.tenant_id + '-Trust';
                    var trustPolicyRoleParams = {
                        "policyDocument": trustPolicyTemplate,
                        "roleName": trustPolicyRoleName
                    };

                    return cognitoUsers.createRole(trustPolicyRoleParams)
                })
                .then(function(trustPolicyRole) {
                    createdTrustPolicyRole = trustPolicyRole;
                    var adminPolicyRoleParams = {
                        PolicyArn: createdAdminPolicy.Policy.Arn,
                        RoleName: createdAdminRole.Role.RoleName
                    };

                    return cognitoUsers.addPolicyToRole(adminPolicyRoleParams);
                })
                .then(function() {
                    var userPolicyRoleParams = {
                        PolicyArn: createdUserPolicy.Policy.Arn,
                        RoleName: createdUserRole.Role.RoleName
                    };

                    return cognitoUsers.addPolicyToRole(userPolicyRoleParams);
                })
                .then(function() {
                    var addRoleToIdentityParams = {
                        "IdentityPoolId": createdIdentityPool.IdentityPoolId,
                        "trustAuthRole": createdTrustPolicyRole.Role.Arn,
                        "rolesystem": createdAdminRole.Role.Arn,
                        "rolesupportOnly": createdUserRole.Role.Arn,
                        "ClientId": createdUserPoolClient.UserPoolClient.ClientId,
                        "provider": createdUserPoolClient.UserPoolClient.UserPoolId,
                        "adminRoleName": adminPolicyName,
                        "userRoleName": userPolicyName
                    };

                    return cognitoUsers.addRoleToIdentity(addRoleToIdentityParams);
                })
                .then(function(identityRole) {
                    var returnObject = {
                        "pool": createdUserPoolData,
                        "userPoolClient": createdUserPoolClient,
                        "identityPool": createdIdentityPool,
                        "role": {
                            "systemAdminRole": createdAdminRole.Role.RoleName,
                            "systemSupportRole": createdUserRole.Role.RoleName,
                            "trustRole": createdTrustPolicyRole.Role.RoleName
                        },
                        "policy": {
                            "systemAdminPolicy": createdAdminPolicy.Policy.Arn,
                            "systemSupportPolicy": createdUserPolicy.Policy.Arn,
                        },
                        "addRoleToIdentity": identityRole
                    };
                    callback(null, returnObject)
                })
                .catch (function(err) {
                    winston.debug(err)
                    callback(err);
                });
        }
    });
}

/**
 * Create a new user using the supplied credentials/user
 * @param credentials The creds used for the user creation
 * @param userPoolId The user pool where the user will be added
 * @param identityPoolId the identityPoolId
 * @param clientId The client identifier
 * @param tenantId The tenant identifier
 * @param newUser The data fro the user being created
 * @param callback Callback with results for created user
 */
function createNewUser(credentials, userPoolId, identityPoolId, clientId, tenantId, newUser) {
    var promise = new Promise(function(resolve, reject) {
        // fill in system attributes for user (not passed in POST)
        newUser.userPoolId = userPoolId;
        newUser.tenant_id = tenantId;
        newUser.email = newUser.userName;
        // cerate the user in Cognito
        cognitoUsers.createUser(credentials, newUser, function (err, cognitoUser) {
            if (err)
                reject(err);
            else {
                // populate the user to store in DynamoDB
                newUser.id = newUser.userName;
                newUser.UserPoolId = userPoolId;
                newUser.IdentityPoolId = identityPoolId;
                newUser.client_id = clientId;
                newUser.tenant_id = tenantId;
                newUser.sub = cognitoUser.User.Attributes[0].Value;

                // construct the helper object
                var dynamoHelper = new DynamoDBHelper(userSchema, credentials, configuration);

                dynamoHelper.putItem(newUser, credentials, function (err, createdUser) {
                    if (err) {
                        reject(err);
                    }
                    else {
                        resolve(null, createdUser)
                    }
                });
            }
        });
    });

    return promise;
}

/**
 * Lookup a user's pool data in the user table
 * @param credentials The credentials used ben looking up the user
 * @param userId The id of the user being looked up
 * @param tenantId The id of the tenant (if this is not system context)
 * @param isSystemContext Is this being called in the context of a system user (registration, system user provisioning)
 * @param callback The results of the lookup
 */
function lookupUserPoolData(credentials, userId, tenantId, isSystemContext, callback) {

    // construct the helper object
    var dynamoHelper = new DynamoDBHelper(userSchema, credentials, configuration);

    // if we're looking this up in a system context, query the GSI with user name only
    if (isSystemContext) {
        var searchParams = {
            TableName: userSchema.TableName,
            IndexName: userSchema.GlobalSecondaryIndexes[0].IndexName,
            KeyConditionExpression: "id = :id",
            ExpressionAttributeValues: {
                ":id": userId
            }
        };

        // get the item from the database
        dynamoHelper.query(searchParams, credentials, function (err, users) {
            if (err) {
                winston.error('Error getting user: ' + err.message);
                callback(err);
            }
            else {
                if (users.length == 0) {
                    var err = new Error('No user found: ' + userId);
                    callback(err);
                }
                else
                    callback(null, users[0]);
            }
        });
    } else {
        var searchParams = {
            id: userId,
            tenant_id: tenantId
        }
        // get the item from the database
        dynamoHelper.getItem(searchParams, credentials, function (err, user) {
            if (err) {
                winston.error('Error getting user: ' + err.message);
                callback(err);
            }
            else {
                callback(null, user);
            }
        });
    }
}

/**
 * Enable/disable a user
 * @param req The request with the user information
 * @param enable True if enabling, False if disabling
 * @param callback Return results of applying enable/disable
 */
function updateUserEnabledStatus(req, enable, callback) {
    var user = req.body;

    tokenManager.getCredentialsFromToken(req, function(credentials) {
        // get the tenant id from the request
        var tenantId = tokenManager.getTenantId(req);

        // Get additional user data required for enabled/disable
        lookupUserPoolData(credentials, user.userName, tenantId, false, function(err, userPoolData) {
            var userPool = userPoolData;

            // if the user pool found, proceed
            if (err) {
                callback(err);
            }
            else {
                // update the user enabled status
                cognitoUsers.updateUserEnabledStatus(credentials, userPool.UserPoolId, user.userName, enable)
                    .then(function() {
                        callback(null, {status: 'success'});
                    })
                    .catch(function(err) {
                        callback(err);
                    });
            }
        });
    });
}

/**
 * Extract a token from the header and return its embedded user pool id
 * @param req The request with the token
 * @returns The user pool id from the token
 */
function getUserPoolIdFromRequest(req) {
    var token = req.get('Authorization');
    var userPoolId;
    var decodedToken = tokenManager.decodeToken(token);
    if (decodedToken) {
        var pool = decodedToken.iss;
        userPoolId = pool.substring(pool.lastIndexOf("/") + 1);
    }
    return userPoolId;
};

// FROM HERE: system service
/**
 * Register a new system admin user
 */
app.post('/sys/admin', function (req, res) {
    var tenant = req.body;

    // Generate the tenant id for the system user
    tenant.id = 'SYSADMIN' + uuidV4();
    winston.debug('Creating system admin user, tenant id: ' + tenant.id);
    tenant.id = tenant.id.split('-').join('');

    // if the system admin user doesn't exist, create one
    tenantExists(tenant, function(tenantExists) {
        if (tenantExists) {
            winston.error("Error registering new system admin user");
            res.status(400).send("Error registering new system admin user");
        }
        else {
            registerSystemTenantAdmin(tenant)
                .then(function (tenData) {
                    //Adding Data to the Tenant Object that will be required to cleaning up all created resources for all tenants.
                    tenant.UserPoolId = tenData.pool.UserPool.Id;
                    tenant.IdentityPoolId = tenData.identityPool.IdentityPoolId;

                    tenant.systemAdminRole = tenData.role.systemAdminRole;
                    tenant.systemSupportRole = tenData.role.systemSupportRole;
                    tenant.trustRole = tenData.role.trustRole;

                    tenant.systemAdminPolicy = tenData.policy.systemAdminPolicy;
                    tenant.systemSupportPolicy = tenData.policy.systemSupportPolicy;

                    tenant.ClientId = tenData.userPoolClient.UserPoolClient.ClientId;

                    saveTenantData(tenant)
                })
                .then(function () {
                    winston.debug("System admin user registered: " + tenant.id);
                    res.status(200).send("System admin user " + tenant.id + " registered");
                })
                .catch(function (error) {
                    winston.error("Error registering new system admin user: " + error.message);
                    res.status(400).send("Error registering system admin user: " + error.message);
                });
        }
    });
});


/**
 * Delete all system infrastructure and tables.
 */
app.delete('/sys/admin', function (req, res) {


    deleteInfra()
        .then(function () {
            winston.debug("Delete Infra");
            //CloudFormation will remove the tables. This can be uncommented if required.
            //deleteTables()
        })
        .then(function () {
            winston.debug("System Infrastructure & Tables removed");
            res.status(200).send("System Infrastructure & Tables removed");
        })
        .catch(function (error) {
            winston.error("Error removing system");
            res.status(400).send(" Error removing system");
        });

});


/**
 * Determine if a system admin user can be created (they may already exist)
 * @param tenant The tenant data
 * @returns True if the tenant exists
 */
function tenantExists(tenant, callback) {
    // Create URL for user-manager request
    var userExistsUrl = userURL + '/pool/' + tenant.userName;

    // see if the user already exists
    request({
        url: userExistsUrl,
        method: "GET",
        json: true,
        headers: {"content-type": "application/json"}
    }, function (error, response, body) {
        if (error)
            callback(false);
        else if ((response != null) && (response.statusCode == 400))
            callback(false);
        else {
            if (body.userName === tenant.userName)
                callback(true);
            else
                callback(false);
        }
    });
};

/**
 * Register a new tenant user and provision policies for that user
 * @param tenant The new tenant data
 * @returns {Promise} Results of tenant provisioning
 */
function registerSystemTenantAdmin(tenant) {
    var promise = new Promise(function(resolve, reject) {

        // init the request with tenant data
        var tenantAdminData = {
            "tenant_id": tenant.id,
            "companyName": tenant.companyName,
            "tier": tenant.tier,
            "email": tenant.email,
            "userName": tenant.userName,
            "role": tenant.role,
            "firstName": tenant.firstName,
            "lastName": tenant.lastName
        };

        // REST API URL
        var registerTenantUserURL = userURL + '/system';

        // fire request
        request({
            url: registerTenantUserURL,
            method: "POST",
            json: true,
            headers: {"content-type": "application/json"},
            body: tenantAdminData
        }, function (error, response, body) {
            if (error || (response.statusCode != 200))
                reject(error)
            else
                resolve(body)
        });
    });

    return promise;
}

/**
 * Delete the User Pools, Identity Pools, Roles, and Policies for all Tenants, and the System Admin.
 * @returns {Promise} The created tenant
 */
function deleteInfra() {
    var promise = new Promise(function(resolve, reject) {

        var deleteInfraUrl = userURL + '/tenants';

        // fire request
        request({
            url: deleteInfraUrl,
            method: "DELETE",
            json: true,
        }, function (error, response) {
            if (error || (response.statusCode != 200))
            {
                reject(error);
                winston.debug('Error Removing Infrastructure');
            }
            else
            {
                resolve(response.statusCode);
                winston.debug('Removed Infrastructure');
            }
        });
    });

    return promise;
}

/**
 * Delete all DynamoDB Tables.
 * @returns {Promise} The created tenant
 */
function deleteTables() {
    var promise = new Promise(function(resolve, reject) {

        var deleteTableUrl = userURL + '/tables';

        // fire request
        request({
            url: deleteTableUrl,
            method: "DELETE",
            json: true,
        }, function (error, response) {
            if (error || (response.statusCode != 200))
            {
                reject(response.statusCode);
                winston.debug('Error Removing Tables');
            }
            else
            {
                resolve(response.statusCode);
                winston.debug('Removed Tables');
            }
        });
    });

    return promise;
}


// app.get('/sys/init_table', function (req, res) {
//     dbHelper.createTable(function (err, tenant) {
//         if (err) {
//             winston.error('Error creating table:');
//             res.status(400).send('{"Error" : "Error creating table"}');
//         }
//         else {
//             res.status(200).send({"status": "success"});
//         }
//     });
// });

// FROM HERE: product service
// Create REST entry points
app.get('/product/:id', function(req, res) {
    winston.debug('Fetching product: ' + req.params.id);

    tokenManager.getCredentialsFromToken(req, function(credentials) {
        // init params structure with request params
        var params = {
            tenantId: tenantId,
            productId: req.params.id
        }
        dbHelper.getProduct(params, function (err, products) {
            if (err) {
                winston.error('Error getting product: ' + err.message);
                res.status(400).send('{"Error" : "Error getting product"}');
            }
            else {
                if (products.length == 0) {
                    winston.error('No product found');
                    res.status(400).send('{"Error" : "No product found"}');
                }
                winston.debug('Product ' + req.params.id + ' retrieved');
                res.status(200).send(products[0]);
            }
        });
    });
});

app.get('/products', function(req, res) {
    // winston.debug('Fetching Products for Tenant Id: ' + tenantId);
    tokenManager.getCredentialsFromToken(req, function(credentials) {
        var tenantId = tokenManager.getTenantId(req);
        console.log(tenantId);
        dbHelper.getProducts(tenantId, function (error, products) {
            if (error) {
                winston.error('Error retrieving products: ' + error.message);
                res.status(400).send('{"Error" : "Error retrieving products"}');
            }
            else {
                winston.debug('Products successfully retrieved');
                res.status(200).send(products);
            }

        });
    });
});

app.post('/product', function(req, res) {
    tokenManager.getCredentialsFromToken(req, function(credentials) {
        var tenantId = tokenManager.getTenantId(req);
        var params = {
            id: uuidV4(),
            tenantId: tenantId,
            unitCost: req.body.unit_cost,
            title: req.body.title
        };

        dbHelper.createProduct(params, function (err, product) {
            if (err) {
                winston.error('Error creating new product: ' + err.message);
                res.status(400).send('{"Error" : "Error creating product"}');
            }
            else {
                winston.debug('Product ' + req.body.title + ' created');
                res.status(200).send({status: 'success'});
            }
        });
    });
});

app.put('/product', function(req, res) {
    winston.debug('Updating product: ' + req.body.productId);
    tokenManager.getCredentialsFromToken(req, function(credentials) {
        var tenantId = tokenManager.getTenantId(req);
        // init the params from the request data
        var productUpdateParams = {
            tenantId: tenantId,
            productId: req.body.productId,
            title: req.body.title,
            unitCost: req.body.unitCost
        }

        winston.debug('Updating product: ' + req.body.productId);

        dbHelper.updateProduct(productUpdateParams, function (err, rowCount) {
            if (err) {
                winston.error('Error updating product: ' + err.message);
                res.status(400).send('{"Error" : "Error updating product"}');
            }
            else {
                if (rowCount == 1) {
                    winston.debug('Product ' + req.body.title + ' updated');
                    res.status(200).send({"status": "success"});
                } else {
                    winston.error('Error updating product');
                    res.status(400).send('{"Error" : "Error updating product"}');
                }
            }
        });
    });
});

app.delete('/product/:id', function(req, res) {
    winston.debug('Deleting product: ' + req.params.id);

    tokenManager.getCredentialsFromToken(req, function(credentials) {
        var tenantId = tokenManager.getTenantId(req);
        var deleteProductParams = {
            tenantId: tenantId,
            productId: req.params.id
        };
        dbHelper.deleteProduct(deleteProductParams, function (err, rowCount) {
            if (err) {
                winston.error('Error deleting product: ' + err.message);
                res.status(400).send('{"Error" : "Error deleting product"}');
            }
            else {
                if (rowCount == 1) {
                    winston.debug('Product ' + req.params.id + ' deleted');
                    res.status(200).send({status: 'success'});
                } else {
                    winston.error('Error deleting product');
                    res.status(400).send('{"Error" : "Error deleting product"}');
                }
            }
        });
    });
});

// FROM HERE: order service

// Start the servers
app.listen(configuration.port.all);
console.log(configuration.name.all + ' service started on port ' + configuration.port.all);
