'use strict';

/**
 * Imports.
 */
const Promise = require('bluebird');
const bcrypt = require('bcryptjs');
const uuid = require('node-uuid');
const core = require('nd-oauth2-core');


/**
 * Class definition.
 */
class DynamoDbProvider {

    /**
     *
     * @param dbClient          The <c>AWS.DynamoDB.DocumentClient</c> instance used to access the underlying database.
     * @param clients           The in-memory OAuth clients registered with the server.
     * @param tokensTable       The AWS DynamoDB table name for storing tokens.
     * @param usersTable        The AWS DynamoDB table name for storing users.
     * @param usernamesTable    The AWS DynamoDB table name for storing usernames (for uniqueness).
     * @param saltFactor        An options integer representing the salt factor for hashing.
     */
    constructor({ dbClient, clients, tokensTable, usersTable, usernamesTable, saltFactor = 10}) {

        // TODO: add validation

        // initialize instance variables
        this.dbClient = dbClient;
        this.clients = clients;
        this.tokensTable = tokensTable;
        this.usersTable = usersTable;
        this.usernamesTable = usernamesTable;
        this.saltFactor = saltFactor;

        // promisify db methods
        this.dbClient.queryAsync = Promise.promisify(dbClient.query, {context: dbClient});
        this.dbClient.getAsync = Promise.promisify(dbClient.get, {context: dbClient});
        this.dbClient.putAsync = Promise.promisify(dbClient.put, {context: dbClient});
        this.dbClient.updateAsync = Promise.promisify(dbClient.update, {context: dbClient});
        this.dbClient.deleteAsync = Promise.promisify(dbClient.delete, {context: dbClient});
    }

    prepare() {

        // create dynamo handle
        const dynamodb = this.dbClient.service;

        // create promises
        const instance = this;
        return Promise.all([
            createTokensTableAsync(dynamodb, instance.tokensTable),
            createUsersTableAsync(dynamodb, instance.usersTable),
            createUsernamesTableAsync(dynamodb, instance.usernamesTable)
        ]);
    }

    createUser(userId, username, password, scopes, enabled, userData) {

        // create user in database
        const instance = this;
        return instance.dbClient

            // create username entry (fails on duplicate)
            .putAsync({
                TableName: instance.usernamesTable,
                Item: {
                    username: username,
                    userId: userId
                },
                ConditionExpression: 'attribute_not_exists(username)'
            })

            // generate password hash
            .then(function() {
                return hashAsync(password, instance.saltFactor);
            })

            // create user entry
            .then(function(passwordHash) {
                return instance.dbClient
                    .putAsync({
                        TableName: instance.usersTable,
                        Item: {
                            id: userId,
                            username: username,
                            passwordHash: passwordHash,
                            scopes: scopes,
                            enabled: enabled,
                            userData: userData
                        }
                    });
            })

            // return user id
            .then(function(userId) {
                return userId;
            })
            .catch(function(error) {

                if (error.code === 'ConditionalCheckFailedException') {
                    error = new core.OAuth2Error(403, 'account_exists', 'Email already exists.')
                }

                throw error;
            });
    }

    getUserById(userId) {

        const instance = this;
        return instance.dbClient
            .getAsync({
                TableName: instance.usersTable,
                Key: {
                    id: userId
                }
            })
            .then(function(data) {

                // capture user
                const user = data.Item;

                // prune user password
                if (user) {
                    delete user.passwordHash;
                }

                return user;
            });
    }

    setUserData(userId, userData) {

        const instance = this;
        return instance.dbClient
            .updateAsync({
                TableName: instance.usersTable,
                Key: {
                    id: userId
                },
                UpdateExpression: 'set userData = :d',
                ExpressionAttributeValues:{
                    ':d': userData
                },
                ReturnValues:'NONE'
            })
            .then(function() {
                return true;
            });
    }

    setUserEnabled(userId, enabled) {

        const instance = this;
        return instance.dbClient
            .updateAsync({
                TableName: instance.usersTable,
                Key: {
                    id: userId
                },
                UpdateExpression: 'set enabled = :e',
                ExpressionAttributeValues:{
                    ':e': enabled
                },
                ReturnValues:'NONE'
            })
            .then(function() {
                return true;
            });
    }

    deleteUser(userId) {

        const instance = this;
        return instance.dbClient
            .deleteAsync({
                TableName: instance.usersTable,
                Key: {
                    id: userId
                }
            })
            .then(function() {
                return true;
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
        return instance.dbClient
            .queryAsync({
                TableName: instance.usersTable,
                IndexName: 'index.username',
                KeyConditionExpression: 'username = :u',
                ExpressionAttributeValues: {
                    ':u': username
                }
            })
            .then(function(data) {

                // capture user
                const user = (data.Items || [null])[0];

                // stop processing if user couldn't be found
                if (!user || !user.passwordHash) {
                    throw new core.OAuth2Error(401, 'invalid_credentials', 'Invalid username or password.')
                }

                // stop processing if user isn't enabled
                if (!user.enabled) {
                    throw new core.OAuth2Error(400, 'account_disabled', 'User account is disabled.');
                }

                // continue processing
                return user;
            })
            .tap(function(user) {
                return hashCompareAsync(password, user.passwordHash)
                    .tap(function(matched) {
                        if (!matched) {
                            throw new core.OAuth2Error(401, 'invalid_credentials', 'Invalid username or password.');
                        }
                    });
            });
    }

    getAccessToken(accessToken) {

        const instance = this;
        return instance.dbClient
            .getAsync({
                TableName: instance.tokensTable,
                Key: {
                    accessToken: accessToken
                }
            })
            .then(function(data) {
                return deserializeToken(data.Item);
            });
    }

    getRefreshToken(refreshToken) {

        const instance = this;
        return instance.dbClient
            .queryAsync({
                TableName: instance.tokensTable,
                IndexName: 'index.refreshToken',
                KeyConditionExpression: 'refreshToken = :r',
                ExpressionAttributeValues: {
                    ':r': refreshToken
                }
            })
            .then(function(data) {
                const tokens = (data.Items || []);
                return tokens.length === 1
                    ? deserializeToken(tokens[0])
                    : null;
            });
    }

    saveToken(token, client, user) {

        // create token
        const tokenData = {
            accessToken: token.accessToken,
            accessTokenExpiry: token.accessTokenExpiresAt.getTime(),
            refreshToken: token.refreshToken,
            refreshTokenExpiry: token.refreshTokenExpiresAt.getTime(),
            userId: user.id,
            clientId: client.id,
            scope: token.scope
        };

        const instance = this;
        return instance.dbClient
            .putAsync({
                TableName: instance.tokensTable,
                Item: tokenData,
                ConditionExpression: 'attribute_not_exists(accessToken)'
            })
            .then(function() {
                return deserializeToken(tokenData);
            })
            .catch(function(error) {

                // TODO: change this to some type of retry
                if (error.code === 'ConditionalCheckFailedException') {
                    error = new core.OAuth2Error(500, 'duplicate_token', 'Token generation already exists.')
                }

                throw error;
            });
    }

    revokeToken(token) {

        const instance = this;
        return instance.dbClient
            .deleteAsync({
                TableName: instance.tokensTable,
                Key: {
                    accessToken: token.accessToken
                }
            })
            .then(function() {

                // mark token as expired
                token.refreshTokenExpiresAt = new Date(0);

                // forward revoked token
                return token;
            });
    }

    validateScope(user, client, scope) {

        // FIXME: check intersection with client scopes to ensure security

        return new Promise(function(resolve) {
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
const hashAsync = Promise.promisify(bcrypt.hash);
const hashCompareAsync = Promise.promisify(bcrypt.compare);

function createTokensTableAsync(dynamodb, tableName) {
    return new Promise(function(resolve, reject) {

        // define table
        const table = {
            TableName : tableName,
            KeySchema: [
                { AttributeName: 'accessToken', KeyType: 'HASH'}
            ],
            AttributeDefinitions: [
                { AttributeName: 'accessToken', AttributeType: 'S' },
                { AttributeName: 'refreshToken', AttributeType: 'S' }
            ],
            GlobalSecondaryIndexes :[
                {
                    IndexName: 'index.refreshToken',
                    KeySchema: [
                        { AttributeName: 'refreshToken', KeyType: 'HASH' }
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

function createUsernamesTableAsync(dynamodb, tableName) {
    return new Promise(function(resolve, reject) {

        // define table
        const table = {
            TableName: tableName,
            KeySchema: [
                {AttributeName: 'username', KeyType: 'HASH'}
            ],
            AttributeDefinitions: [
                {AttributeName: 'username', AttributeType: 'S'},
                {AttributeName: 'userId', AttributeType: 'S'}
            ],
            GlobalSecondaryIndexes: [
                {
                    IndexName: 'index.userId',
                    KeySchema: [
                        {AttributeName: 'userId', KeyType: 'HASH'}
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
        accessToken: tokenData.accessToken,
        accessTokenExpiresAt: new Date(tokenData.accessTokenExpiry),
        refreshToken: tokenData.refreshToken,
        refreshTokenExpiresAt: new Date(tokenData.refreshTokenExpiry),
        user: {
            id: tokenData.userId
        },
        client: {
            id: tokenData.clientId
        },
        scope: tokenData.scope
    };
    return token;
}


/**
 * Exports.
 *
 * @type {DynamoDbProvider}
 */
module.exports = DynamoDbProvider;
