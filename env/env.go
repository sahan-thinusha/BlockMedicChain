package env

import (
	mongo "go.mongodb.org/mongo-driver/mongo"
)

var MDB *mongo.Database
var MClient *mongo.Client

var DEFAULTdb string
var DEFAULTDIALET string
var DEFAULThost string
var DEFAULTport string
var DEFAULTpwd string
var DEFAULTurl string
var DEFAULTuser string
var GRPCPORT string
var NATSport string
var NATSurl string
var RESTPORT string
var JWTsecret string
var URL = "mongodb+srv://blockmedic:bm12345@cluster0.ppqd4.mongodb.net/BlockMedic?retryWrites=true&w=majority"
