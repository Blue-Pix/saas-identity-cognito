'use strict';

//  Express
const express = require('express');
const bodyParser = require('body-parser');

// UUID Generator Module
const uuidV4 = require('uuid/v4');

// Configure Environment
const configModule = require('../shared-modules/config-helper/config.js');
var configuration = configModule.configure(process.env.NODE_ENV);

// Configure Logging
const winston = require('winston');
winston.level = configuration.loglevel;

// Include Custom Modules
const tokenManager = require('../shared-modules/token-manager/token-manager.js');

const DBHelper = require('../shared-modules/db-helper/db-helper.js');
const dbHelper = new DBHelper();

// Instantiate application
var app = express();
var bearerToken = '';
var tenantId = '';

// Configure middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, PATCH, DELETE");
    res.header("Access-Control-Allow-Headers", "Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");
    bearerToken = req.get('Authorization');
    if (bearerToken) {
        tenantId = tokenManager.getTenantId(req);
    }
    next();
});

app.get('/product/health', function(req, res) {
    res.status(200).send({service: 'Product Manager', isAlive: true});
});

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
    winston.debug('Fetching Products for Tenant Id: ' + tenantId);
    tokenManager.getCredentialsFromToken(req, function(credentials) {
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




// Start the servers
app.listen(configuration.port.product);
console.log(configuration.name.product + ' service started on port ' + configuration.port.product);
