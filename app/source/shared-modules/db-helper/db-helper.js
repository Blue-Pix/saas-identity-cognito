'use strict';

//Configure Environment
const configModule = require('../config-helper/config.js');
var configuration = configModule.configure(process.env.NODE_ENV);

//Configure Logging
const winston = require('winston');
winston.level = configuration.loglevel;

const { Pool } = require('pg')
const pool = new Pool()

/**
 * Constructor function
 * @param tableDefinition The defintion of the table being used
 * @param configSettings Configuration settings
 * @constructor
 */
function DBHelper() {
    this.pool = new Pool();
}

/**
 * Query for items using the supplied parameters
 * @param searchParameters The search parameters
 * @param credentials The user creds
 * @param callback Callback function for results
 */
DBHelper.prototype.lookupUser = function(params, callback) {
    this.pool.connect(function(err, client) {
        if (err) {
            winston.error("Unable to connect db. Error:", JSON.stringify(err, null, 2));
            callback(err);
        } else {
            // [Todo] tenantId is optional
            client.query("SELECT * FROM users where id = $1", [params.id], function (err, result) {
                if (err) {
                    winston.error("Unable to query. Error:", JSON.stringify(err, null, 2));
                    callback(err);
                } else {
                    callback(null, result.rows);
                }
            });
        }
    });
}

DBHelper.prototype.lookupTenant = function(params, callback) {
    this.pool.connect(function(err, client) {
        if (err) {
            winston.error("Unable to connect db. Error:", JSON.stringify(err, null, 2));
            callback(err);
        } else {
            // [Todo] tenantId is optional
            client.query("SELECT * FROM tenants where id = $1", [params.id], function (err, result) {
                if (err) {
                    winston.error("Unable to query. Error:", JSON.stringify(err, null, 2));
                    callback(err);
                } else {
                    callback(null, result.rows);
                }
            });
        }
    });
}

DBHelper.prototype.getUser = function(params, callback) {
    this.pool.connect(function(err, client) {
        if (err) {
            winston.error("Unable to connect db. Error:", JSON.stringify(err, null, 2));
            callback(err);
        } else {
            // [Todo] tenantId is optional
            client.query("SELECT * FROM users where id = $1 and tenant_id = $2", [params.id, params.tenant_id], function (err, result) {
                if (err) {
                    winston.error("Unable to query. Error:", JSON.stringify(err, null, 2));
                    callback(err);
                } else {
                    if (result.rows.length == 0) {
                        callback(new Error("No user record found"));
                    } else {
                        callback(null, result.rows[0]);
                    }
                }
            });
        }
    });
}

DBHelper.prototype.getTenants = function(credentials, callback) {
    this.pool.connect(function(err, client) {
        if (err) {
            winston.error("Unable to connect db. Error:", JSON.stringify(err, null, 2));
            callback(err);
        } else {
            // [Todo] tenantId is optional
            client.query("SELECT * FROM tenants", function (err, result) {
                if (err) {
                    winston.error("Unable to query. Error:", JSON.stringify(err, null, 2));
                    callback(err);
                } else {
                    callback(null, result.rows);
                }
            });
        }
    });
}

DBHelper.prototype.createTenant = function(params, callback) {
    this.pool.connect(function(err, client) {
        if (err) {
            winston.error("Unable to connect db. Error:", JSON.stringify(err, null, 2));
            callback(err);
        } else {
            var statement = `INSERT INTO tenants(
                id, company_name, tier, identity_pool_id, user_pool_id, client_id, system_admin_role, 
                system_support_role, trust_role, system_admin_policy, system_support_policy
            ) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            `;
            var placeHolders = [
                params.id, params.companyName, params.tier, params.IdentityPoolId,
                params.UserPoolId, params.ClientId, params.systemAdminRole, params.systemSupportRole,
                params.trustRole, params.systemAdminPolicy, params.systemSupportPolicy
            ]
            client.query(statement, placeHolders, function (err, result) {
                if (err) {
                    winston.error("Unable to query. Error:", JSON.stringify(err, null, 2));
                    callback(err);
                } else {
                    callback(null, result.rowCount);
                }
            });
        }
    });
}

DBHelper.prototype.createUser = function(params, callback) {
    this.pool.connect(function(err, client) {
        if (err) {
            winston.error("Unable to connect db. Error:", JSON.stringify(err, null, 2));
            callback(err);
        } else {
            var statement = `INSERT INTO users(
                id, tenant_id, role, first_name, family_name, email
            ) values ($1, $2, $3, $4, $5, $6)
            `;
            var placeHolders = [
                params.id, params.tenant_id, params.role, params.firstName,
                params.lastName, params.email
            ]
            client.query(statement, placeHolders, function (err, result) {
                if (err) {
                    winston.error("Unable to query. Error:", JSON.stringify(err, null, 2));
                    callback(err);
                } else {
                    callback(null, result.rowCount);
                }
            });
        }
    });
}

DBHelper.prototype.createProduct = function(params, callback) {
    this.pool.connect(function(err, client) {
        if (err) {
            winston.error("Unable to connect db. Error:", JSON.stringify(err, null, 2));
            callback(err);
        } else {
            var statement = `INSERT INTO products(
                id, tenant_id, title, unit_cost
            ) values ($1, $2, $3, $4)
            `;
            var placeHolders = [
                params.id, params.tenantId, params.title, params.unitCost
            ];
            client.query(statement, placeHolders, function (err, result) {
                if (err) {
                    winston.error("Unable to query. Error:", JSON.stringify(err, null, 2));
                    callback(err);
                } else {
                    callback(null, result.rowCount);
                }
            });
        }
    });
}

DBHelper.prototype.getProducts = function(tenantId, callback) {
    this.pool.connect(function(err, client) {
        if (err) {
            winston.error("Unable to connect db. Error:", JSON.stringify(err, null, 2));
            callback(err);
        } else {
            client.query("SELECT * FROM products where tenant_id = $1", [tenantId], function (err, result) {
                if (err) {
                    winston.error("Unable to query. Error:", JSON.stringify(err, null, 2));
                    callback(err);
                } else {
                    callback(null, result.rows);
                }
            });
        }
    });
}

DBHelper.prototype.getProduct = function(params, callback) {
    this.pool.connect(function(err, client) {
        if (err) {
            winston.error("Unable to connect db. Error:", JSON.stringify(err, null, 2));
            callback(err);
        } else {
            client.query("SELECT * FROM products where id = $1 and tenant_id = $2", [params.productId, params.tenantId], function (err, result) {
                if (err) {
                    winston.error("Unable to query. Error:", JSON.stringify(err, null, 2));
                    callback(err);
                } else {
                    callback(null, result.rows);
                }
            });
        }
    });
}

DBHelper.prototype.updateProduct = function(params, callback) {
    this.pool.connect(function(err, client) {
        if (err) {
            winston.error("Unable to connect db. Error:", JSON.stringify(err, null, 2));
            callback(err);
        } else {
            client.query("UPDATE products set title = $1, unit_cost = $2 where id = $3 and tenant_id = $4", [params.title, params.unitCost, params.productId, params.tenantId], function (err, result) {
                if (err) {
                    winston.error("Unable to query. Error:", JSON.stringify(err, null, 2));
                    callback(err);
                } else {
                    callback(null, result.rowCount);
                }
            });
        }
    });
}

DBHelper.prototype.deleteProduct = function(params, callback) {
    this.pool.connect(function(err, client) {
        if (err) {
            winston.error("Unable to connect db. Error:", JSON.stringify(err, null, 2));
            callback(err);
        } else {
            client.query("DELETE FROM products where id = $1 and tenant_id = $2", [params.productId, params.tenantId], function (err, result) {
                if (err) {
                    winston.error("Unable to query. Error:", JSON.stringify(err, null, 2));
                    callback(err);
                } else {
                    callback(null, result.rowCount);
                }
            });
        }
    });
}

DBHelper.prototype.createTable = function(callback) {
    var statement = `
CREATE TABLE tenants (
    id VARCHAR(255) NOT NULL,
    company_name VARCHAR(255) NOT NULL,
    tier VARCHAR(10) NOT NULL,
    identity_pool_id VARCHAR(255),
    user_pool_id VARCHAR(255),
    client_id VARCHAR(255),
    system_admin_role VARCHAR(255),
    system_support_role VARCHAR(255),
    trust_role VARCHAR(255),
    system_admin_policy VARCHAR(255),
    system_support_policy VARCHAR(255),
    status VARCHAR(255) DEFAULT 'active'
);

CREATE TABLE users (
    id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    role VARCHAR(255) NOT NULL,
    first_name VARCHAR(255),
    family_name VARCHAR(255),
    email VARCHAR(255)
);

CREATE TABLE products (
    id VARCHAR(255) NOT NULL,
    tenant_id VARCHAR(255) NOT NULL,
    title VARCHAR(255) NOT NULL,
    unit_cost INT NOT NULL
);`
    this.pool.connect(function(err, client) {
        if (err) {
            winston.error("Unable to connect db. Error:", JSON.stringify(err, null, 2));
            callback(err);
        } else {
            client.query(statement, function (err, result) {
                if (err) {
                    winston.error("Failed to create table. Error:", JSON.stringify(err, null, 2));
                    callback(err);
                } else {
                    winston.debug("Success to create table");
                    callback(null, 1);
                } 
            }) 
        }
    });
}

module.exports = DBHelper;