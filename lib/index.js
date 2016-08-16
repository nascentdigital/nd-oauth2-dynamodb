'use strict';

// imports
const Promise = require('bluebird');
const bcrypt = require('bcryptjs');
const uuid = require('node-uuid');
const core = require('nd-oauth2-core');


// exports

/**
 * Creates a new instance of the DynamoDB Nascent OAuth2 provider.
 *
 * @param options               Configuration options for the OAuth2 provider.
 * @oaram options.dbClient      The <c>AWS.DynamoDB.DocumentClient</c> instance used to access the underlying database.
 * @param options.client        The in-memory OAuth clients registered with the server.
 * @param options.tokensTable   The AWS DynamoDB table name for storing tokens.
 * @param options.usersTable    The AWS DynamoDB table name for storing users.
 * @param options.saltFactor    An options integer representing the salt factor for hashing.
 *
 * @returns {DynamoDbProvider}  A new provider instance for use with the Nascent OAuth2 server.
 */
module.exports = function(options) {
    return new DynamoDbProvider(options);
};


// class definition
class DynamoDbProvider {

    constructor(options) {

        // TODO: add validation

        // initialize instance variables
        this.dbClient = options.dbClient;
        this.clients = options.clients;
        this.tokensTable = options.tokensTable;
        this.usersTable = options.usersTable;
        this.saltFactor = options.saltFactor || 10;
    }

    prepare() {

        // create dynamo handle
        const dynamodb = this.dbClient.service;

        // create promises
        const instance = this;
        return Promise.all([
            createTokensTableAsync(dynamodb, instance.tokensTable),
            createUsersTableAsync(dynamodb, instance.usersTable)
        ]);
    }

    createUser(username, password, scopes, enabled, userData) {

        const instance = this;
        return new Promise(function(resolve, reject) {

            // hash password
            bcrypt.hash(password, instance.saltFactor, function(err, passwordHash) {

                // stop on error
                if (err) {
                    return reject(err);
                }

                // persist
                const userId = uuid.v4();
                const options = {
                    TableName: instance.usersTable,
                    Item: {
                        id: userId,
                        username: username,
                        password_hash: passwordHash,
                        scopes: scopes,
                        enabled: enabled,
                        user_data: userData
                    }
                };
                instance.dbClient.put(options, function (err, data) {
                    if (err) {
                        return reject(err);
                    }
                    else {
                        return resolve(userId);
                    }
                });
            });
        });
    }

    getUserById(userId) {

        const instance = this;
        return new Promise(function(resolve, reject) {

            // query
            var options = {
                TableName: instance.usersTable,
                Key: {
                    id: userId
                }
            };
            instance.dbClient.get(options, function (err, data) {
                if (err) {
                    reject(err);
                }
                else {

                    // capture user
                    const user = data.Item;

                    // prune user password
                    if (user) {
                        delete user.password_hash;
                    }

                    // return result
                    resolve(user);
                }
            });
        });
    }

    setUserData(userId, userData) {

        const instance = this;
        return new Promise(function(resolve, reject) {

            // query
            var options = {
                TableName: instance.usersTable,
                Key: {
                    id: userId
                },
                UpdateExpression: 'set user_data = :d',
                ExpressionAttributeValues:{
                    ':d': userData
                },
                ReturnValues:'NONE'
            };
            instance.dbClient.update(options, function (err, data) {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(true);
                }
            });
        });
    }

    setUserEnabled(userId, enabled) {

        const instance = this;
        return new Promise(function(resolve, reject) {

            // query
            var options = {
                TableName: instance.usersTable,
                Key: {
                    id: userId
                },
                UpdateExpression: 'set enabled = :e',
                ExpressionAttributeValues:{
                    ':e': enabled
                },
                ReturnValues:'NONE'
            };
            instance.dbClient.update(options, function (err, data) {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(true);
                }
            });
        });
    }

    deleteUser(userId) {

        const instance = this;
        return new Promise(function(resolve, reject) {

            // query
            var options = {
                TableName: instance.usersTable,
                Key: {
                    id: userId
                }
            };
            instance.dbClient.delete(options, function (err, data) {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(true);
                }
            });
        });
    }

    getClient(clientId, clientSecret) {

        const instance = this;
        return new Promise(function(resolve, reject) {

            console.log('fetching clients');

            // search for matching client
            for (var i in instance.clients) {

                // find matching client
                const client = instance.clients[i];
                if (client.id === clientId) {

                    // return grants if the secret matches
                    if (client.secret === clientSecret) {
                        return resolve(client);
                    }

                    // or stop processing (results in error)
                    break;
                }
            }

            // or raise error
            return resolve(null);
        });
    }

    getUser(username, password) {

        const instance = this;
        return new Promise(function(resolve, reject) {

            // query
            var options = {
                TableName: instance.usersTable,
                IndexName: 'index.username',
                KeyConditionExpression: 'username = :u',
                ExpressionAttributeValues: {
                    ':u': username
                }
            };
            instance.dbClient.query(options, function (err, data) {
                if (err) {
                    return reject(err);
                }

                // capture user
                const user = (data.Items || [null])[0];

                // stop processing if user couldn't be found
                if (!user || !user.password_hash) {
                    return resolve(null);
                }

                // stop processing if user isn't enabled
                if (!user.enabled) {
                    return reject(new core.OAuth2Error(400, 'account_disabled', 'User account is disabled'));
                }

                // compare password
                bcrypt.compare(password, user.password_hash, function(err, res) {

                    // stop processing on error
                    if (err) {
                        return reject(err);
                    }

                    // remove password
                    delete user.password_hash;

                    // or return user if passwords match
                    return resolve(res === true ? user : null);
                });
            });
        });
    }

    getAccessToken(accessToken) {

        const instance = this;
        return new Promise(function(resolve, reject) {

            // query
            var options = {
                TableName: instance.tokensTable,
                Key: {
                    access_token: accessToken
                }
            };
            instance.dbClient.get(options, function (err, data) {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(deserializeToken(data.Item));
                }
            });
        });
    }

    getRefreshToken(refreshToken) {

        const instance = this;
        return new Promise(function(resolve, reject) {

            // query
            var options = {
                TableName: instance.tokensTable,
                IndexName: 'index.refresh_token',
                KeyConditionExpression: 'refresh_token = :r',
                ExpressionAttributeValues: {
                    ':r': refreshToken
                }
            };
            instance.dbClient.query(options, function (err, data) {
                if (err) {
                    return reject(err);
                }

                const items = data.Items || [];
                if (items.length === 1) {
                    return resolve(deserializeToken(items[0]));
                }
                else {
                    return resolve(null);
                }
            });
        });
    }

    saveToken(token, client, user) {

        const instance = this;
        return new Promise(function(resolve, reject) {

            // persist
            var options = {
                TableName: instance.tokensTable,
                Item: {
                    access_token: token.accessToken,
                    access_token_expiry: token.accessTokenExpiresAt.getTime(),
                    refresh_token: token.refreshToken,
                    refresh_token_expiry: token.refreshTokenExpiresAt.getTime(),
                    user_id: user.id,
                    client_id: client.id,
                    scope: token.scope
                }
            };
            instance.dbClient.put(options, function (err, data) {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(deserializeToken(options.Item));
                }
            });
        });
    }

    revokeToken(token) {

        const instance = this;
        return new Promise(function(resolve, reject) {

            // query
            var options = {
                TableName: instance.tokensTable,
                Key: {
                    access_token: token.accessToken
                }
            };
            instance.dbClient.delete(options, function (err, data) {
                if (err) {
                    reject(err);
                }
                else {

                    // mark token as expired
                    token.refreshTokenExpiresAt = new Date(0);

                    // forward token to finalize revoke
                    resolve(token);
                }
            });
        });
    }

    validateScope(user, client, scope) {

        // FIXME: check intersection with client scopes to ensure security

        return new Promise(function(resolve, reject) {
            if (user.scopes.indexOf(scope) >= 0) {
                resolve(scope);
            }
            else {
                resolve(false);
            }
        });
    }
}


// helper methods
function createTokensTableAsync(dynamodb, tableName) {
    return new Promise(function(resolve, reject) {

        // define table
        const table = {
            TableName : tableName,
            KeySchema: [
                { AttributeName: 'access_token', KeyType: 'HASH'}
            ],
            AttributeDefinitions: [
                { AttributeName: 'access_token', AttributeType: 'S' },
                { AttributeName: 'refresh_token', AttributeType: 'S' }
            ],
            GlobalSecondaryIndexes :[
                {
                    IndexName: 'index.refresh_token',
                    KeySchema: [
                        { AttributeName: 'refresh_token', KeyType: 'HASH' }
                    ],
                    Projection: {
                        ProjectionType: 'ALL'
                    },
                    ProvisionedThroughput: {
                        ReadCapacityUnits: 2,
                        WriteCapacityUnits: 1
                    }
                }
            ],
            ProvisionedThroughput: {
                ReadCapacityUnits: 2,
                WriteCapacityUnits: 1
            }
        };

        // create table
        dynamodb.createTable(table, function(e, data) {
            if (e) {
                reject(e)
            } else {
                resolve(data);
            }
        });
    });
}
function createUsersTableAsync(dynamodb, tableName) {
    return new Promise(function(resolve, reject) {

        // define table
        const table = {
            TableName: tableName,
            KeySchema: [
                {AttributeName: 'id', KeyType: 'HASH'}
            ],
            AttributeDefinitions: [
                {AttributeName: 'id', AttributeType: 'S'},
                {AttributeName: 'username', AttributeType: 'S'}
            ],
            GlobalSecondaryIndexes: [
                {
                    IndexName: 'index.username',
                    KeySchema: [
                        {AttributeName: 'username', KeyType: 'HASH'}
                    ],
                    Projection: {
                        ProjectionType: 'ALL'
                    },
                    ProvisionedThroughput: {
                        ReadCapacityUnits: 1,
                        WriteCapacityUnits: 1
                    }
                }
            ],
            ProvisionedThroughput: {
                ReadCapacityUnits: 2,
                WriteCapacityUnits: 1
            }
        };

        // create table
        dynamodb.createTable(table, function (e, data) {
            if (e) {
                reject(e)
            } else {
                resolve(data);
            }
        });
    });
}
function deserializeToken(tokenData) {

    if (!tokenData) {
        return null;
    }

    const token = {
        accessToken: tokenData.access_token,
        accessTokenExpiresAt: new Date(tokenData.access_token_expiry),
        refreshToken: tokenData.refresh_token,
        refreshTokenExpiresAt: new Date(tokenData.refresh_token_expiry),
        user: {
            id: tokenData.user_id
        },
        client: {
            id: tokenData.client_id
        },
        scope: tokenData.scope
    };
    return token;
}