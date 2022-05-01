package main

import (
	"BlockMedicChain/env"
	_ "bytes"
	"context"
	_ "encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"io/ioutil"
	"net/http"
	_ "strconv"
	"time"
	_ "time"
)

import (
	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
)

type HealthReport struct {
	ID                  string    `bson:"_id" json:"node"`
	Name                string    `json:"name"`
	ContactNo           string    `json:"contactno"`
	Address             string    `json:"address"`
	Nationality         string    `json:"nationality"`
	DOB                 string    `json:"dob"`
	Weight              string    `json:"weight"`
	BloodPressure       string    `json:"bloodPressure"`
	BloodSugar          string    `json:"bloodsugar"`
	Allergies           string    `json:"allergies"`
	Illness             string    `json:"illness"`
	CovidVaccineDetails string    `json:"covidvaccinedetails"`
	EmergencyContact    string    `json:"emergencycontact"`
	PreviousNode        string    `json:"previous_node"`
	UserId              string    `json:"user_id"`
	CreatedAt           time.Time `bson:"created_at" json:"-"`
}

func main() {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	env.JWTsecret = "secret"

	r := e.Group("/api")
	v1 := r.Group("/v1")
	v1.Use(middleware.JWTWithConfig(middleware.JWTConfig{
		ParseTokenFunc: func(auth string, c echo.Context) (interface{}, error) {
			keyFunc := func(t *jwt.Token) (interface{}, error) {
				return []byte(env.JWTsecret), nil
			}
			token, err := jwt.Parse(auth, keyFunc)
			if err != nil {
				return nil, err
			}
			if !token.Valid {
				return nil, errors.New("invalid token")
			}
			return token, nil
		},
	}))
	v1.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			customClaimsJWT := c.Get("user").(*jwt.Token)
			jwtClaims := customClaimsJWT.Claims.(jwt.MapClaims)
			c.Set("UserId", jwtClaims["UserId"])
			return next(c)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(
		env.URL,
	))
	if err != nil {
		fmt.Println(err)
	}
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		fmt.Println(err)
	}
	env.DEFAULTdb = "BlockMedic"
	env.MClient = client
	env.MDB = client.Database(env.DEFAULTdb)

	v1.POST("/savehealthreport", saveHealthReport)
	v1.GET("/gethealthreportfromuser", getReportByUser)
	v1.GET("/gethealthreport", getReportByNode)
	r.GET("/jwt", getJWT)
	e.Logger.Fatal(e.Start(":8080"))
}

type Chaincode struct {
}

func (t *Chaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	//TODO implement me
	panic("implement me")
}

func gg() {
	err := shim.Start(new(Chaincode))
	if err != nil {
		fmt.Printf("Error starting Simple chaincode: %s", err)
	}
}

func (t *Chaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	return shim.Success(nil)
} /*

func (t *Chaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	function, args := stub.GetFunctionAndParameters()
	fmt.Println("invoke is running " + function)

	if function == "initOrder" {
		return t.initOrder(stub, args)
	} else if function == "changeStatus" {
		return t.changeStatus(stub, args)
	} else if function == "changeProvider_id" {
		return t.changeProvider_id(stub, args)
	} else if function == "changeQuantity" {
		return t.changeQuantity(stub, args)
	} else if function == "readOrder" {
		return t.readOrder(stub, args)
	} else if function == "getHistoryForOrder" {
		return t.getHistoryForOrder(stub, args)
	} else if function == "getOrdersByRange" {
		return t.getOrdersByRange(stub, args)
	} else if function == "queryOrderByOrder_medicine_id" {
		return t.queryOrderByOrder_medicine_id(stub, args)
	} else if function == "readOrderPrivateDetails" {
		return t.readOrderPrivateDetails(stub, args)
	} else if function == "changeOrderPrivateDetails" {
		return t.changeOrderPrivateDetails(stub, args)
	}

	fmt.Println("invoke did not find func: " + function)
	return shim.Error("Received unknown function invocation")
}

func (t *Chaincode) initOrder(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var err error

	if len(args) != 7 {
		return shim.Error("Incorrect number of arguments. Expecting 7")
	}

	fmt.Println("- start init order")
	if len(args[0]) <= 0 {
		return shim.Error("1st argument must be a non-empty string")
	}
	if len(args[1]) <= 0 {
		return shim.Error("2nd argument must be a non-empty string")
	}
	if len(args[2]) <= 0 {
		return shim.Error("3rd argument must be a non-empty string")
	}
	if len(args[3]) <= 0 {
		return shim.Error("4th argument must be a non-empty string")
	}
	if len(args[4]) <= 0 {
		return shim.Error("5th argument must be a non-empty string")
	}
	if len(args[5]) <= 0 {
		return shim.Error("6th argument must be a non-empty string")
	}
	if len(args[6]) <= 0 {
		return shim.Error("7th argument must be a non-empty string")
	}

	orderName := args[0]
	manufacturer_id := args[1]
	provider_id := args[2]
	material_name := args[3]
	order_medicine_id := args[4]
	quantity := args[5]
	status := args[6]

	orderAsBytes, err := stub.GetState(orderName)
	if err != nil {
		return shim.Error("Failed to get order: " + err.Error())
	} else if orderAsBytes != nil {
		fmt.Println("This orderName already exists: " + orderName)
		return shim.Error("This orderName already exists: " + orderName)
	}

	objectType := "order"
	order := &order{objectType, orderName, manufacturer_id, provider_id, material_name, order_medicine_id, quantity, status}
	orderJSONasBytes, err := json.Marshal(order)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = stub.PutState(orderName, orderJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	// ==== Create order private details object with price, marshal to JSON, and save to state ====
	transMap, err := stub.GetTransient()
	if err != nil {
		return shim.Error("Error getting transient: " + err.Error())
	}

	if _, ok := transMap["order"]; !ok {
		return shim.Error("order must be a key in the transient map")
	}

	if len(transMap["order"]) == 0 {
		return shim.Error("order value in the transient map must be a non-empty JSON string")
	}

	type orderTransientInput struct {
		Price string `json:"price"`
	}

	var orderInput orderTransientInput
	err = json.Unmarshal(transMap["order"], &orderInput)
	if err != nil {
		return shim.Error("Failed to decode JSON of: " + string(transMap["order"]))
	}

	orderPrivateDetails := &orderPrivateDetails{
		Price: orderInput.Price,
	}
	orderPrivateDetailsBytes, err := json.Marshal(orderPrivateDetails)
	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutPrivateData("collectionMaterialOrderPrivateDetails", orderName, orderPrivateDetailsBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	indexName := "order_medicine_id"
	order_medicine_idIndexKey, err := stub.CreateCompositeKey(indexName, []string{order.Order_medicine_id, order.Order_raw_material_id})
	if err != nil {
		return shim.Error(err.Error())
	}

	value := []byte{0x00}
	stub.PutState(order_medicine_idIndexKey, value)

	fmt.Println("- end init order")
	return shim.Success(nil)
}

func (t *Chaincode) readOrder(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var name, jsonResp string
	var err error

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting name of the order to query")
	}

	name = args[0]
	valAsbytes, err := stub.GetState(name)
	if err != nil {
		jsonResp = "{\"Error\":\"Failed to get state for " + name + "\"}"
		return shim.Error(jsonResp)
	} else if valAsbytes == nil {
		jsonResp = "{\"Error\":\"Order does not exist: " + name + "\"}"
		return shim.Error(jsonResp)
	}

	return shim.Success(valAsbytes)
}

func (t *Chaincode) changeStatus(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	if len(args) < 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2")
	}

	orderName := args[0]
	newStatus := args[1]
	fmt.Println("- start changeStatus ", orderName, newStatus)

	orderAsBytes, err := stub.GetState(orderName)
	if err != nil {
		return shim.Error("Failed to get order:" + err.Error())
	} else if orderAsBytes == nil {
		return shim.Error("Order does not exist")
	}

	statusToChange := order{}
	err = json.Unmarshal(orderAsBytes, &statusToChange)
	if err != nil {
		return shim.Error(err.Error())
	}
	statusToChange.Status = newStatus

	orderJSONasBytes, _ := json.Marshal(statusToChange)
	err = stub.PutState(orderName, orderJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	fmt.Println("- end changeStatus (success)")
	return shim.Success(nil)
}

func (t *Chaincode) changeProvider_id(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	if len(args) < 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2")
	}

	orderName := args[0]
	newProvider_id := args[1]
	fmt.Println("- start changeStatus ", orderName, newProvider_id)

	orderAsBytes, err := stub.GetState(orderName)
	if err != nil {
		return shim.Error("Failed to get order:" + err.Error())
	} else if orderAsBytes == nil {
		return shim.Error("Order does not exist")
	}

	provider_idToChange := order{}
	err = json.Unmarshal(orderAsBytes, &provider_idToChange)
	if err != nil {
		return shim.Error(err.Error())
	}

	orderJSONasBytes, _ := json.Marshal(provider_idToChange)
	err = stub.PutState(orderName, orderJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	fmt.Println("- end changeStatus (success)")
	return shim.Success(nil)
}

func (t *Chaincode) changeQuantity(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	if len(args) < 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2")
	}

	orderName := args[0]
	newQuantity := args[1]
	fmt.Println("- start changeStatus ", orderName, newQuantity)

	orderAsBytes, err := stub.GetState(orderName)
	if err != nil {
		return shim.Error("Failed to get order:" + err.Error())
	} else if orderAsBytes == nil {
		return shim.Error("Order does not exist")
	}

	quantityToChange := order{}
	err = json.Unmarshal(orderAsBytes, &quantityToChange)
	if err != nil {
		return shim.Error(err.Error())
	}
	quantityToChange.Quantity = newQuantity

	orderJSONasBytes, _ := json.Marshal(quantityToChange)
	err = stub.PutState(orderName, orderJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	fmt.Println("- end changeStatus (success)")
	return shim.Success(nil)
}

func (t *Chaincode) queryOrderByOrder_medicine_id(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	if len(args) < 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	order_medicine_id := args[0]

	queryString := fmt.Sprintf("{\"selector\":{\"docType\":\"order\",\"order_medicine_id\":\"%s\"}}", order_medicine_id)

	queryResults, err := getQueryResultForQueryString(stub, queryString)
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(queryResults)
}

func getQueryResultForQueryString(stub shim.ChaincodeStubInterface, queryString string) ([]byte, error) {

	fmt.Printf("- getQueryResultForQueryString queryString:\n%s\n", queryString)

	resultsIterator, err := stub.GetQueryResult(queryString)
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	buffer, err := constructQueryResponseFromIterator(resultsIterator)
	if err != nil {
		return nil, err
	}

	fmt.Printf("- getQueryResultForQueryString queryResult:\n%s\n", buffer.String())

	return buffer.Bytes(), nil
}

func constructQueryResponseFromIterator(resultsIterator shim.StateQueryIteratorInterface) (*bytes.Buffer, error) {

	var buffer bytes.Buffer
	buffer.WriteString("[")

	bArrayMemberAlreadyWritten := false
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		if bArrayMemberAlreadyWritten == true {
			buffer.WriteString(",")
		}
		buffer.WriteString("{\"Key\":")
		buffer.WriteString("\"")
		buffer.WriteString(queryResponse.Key)
		buffer.WriteString("\"")

		buffer.WriteString(", \"Record\":")
		buffer.WriteString(string(queryResponse.Value))
		buffer.WriteString("}")
		bArrayMemberAlreadyWritten = true
	}
	buffer.WriteString("]")

	return &buffer, nil
}

func (t *Chaincode) getHistoryForOrder(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	if len(args) < 1 {
		return shim.Error("Incorrect number of arguments. Expecting 1")
	}

	orderName := args[0]

	fmt.Printf("- start getHistoryForOrder: %s\n", orderName)

	resultsIterator, err := stub.GetHistoryForKey(orderName)
	if err != nil {
		return shim.Error(err.Error())
	}
	defer resultsIterator.Close()

	var buffer bytes.Buffer
	buffer.WriteString("[")

	bArrayMemberAlreadyWritten := false
	for resultsIterator.HasNext() {
		response, err := resultsIterator.Next()
		if err != nil {
			return shim.Error(err.Error())
		}

		if bArrayMemberAlreadyWritten == true {
			buffer.WriteString(",")
		}
		buffer.WriteString("{\"TxId\":")
		buffer.WriteString("\"")
		buffer.WriteString(response.TxId)
		buffer.WriteString("\"")

		buffer.WriteString(", \"Value\":")

		if response.IsDelete {
			buffer.WriteString("null")
		} else {
			buffer.WriteString(string(response.Value))
		}

		buffer.WriteString(", \"Timestamp\":")
		buffer.WriteString("\"")
		buffer.WriteString(time.Unix(response.Timestamp.Seconds, int64(response.Timestamp.Nanos)).String())
		buffer.WriteString("\"")

		buffer.WriteString(", \"IsDelete\":")
		buffer.WriteString("\"")
		buffer.WriteString(strconv.FormatBool(response.IsDelete))
		buffer.WriteString("\"")

		buffer.WriteString("}")
		bArrayMemberAlreadyWritten = true
	}
	buffer.WriteString("]")

	fmt.Printf("- getHistoryForOrder returning:\n%s\n", buffer.String())

	return shim.Success(buffer.Bytes())
}

func (t *Chaincode) getOrdersByRange(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	if len(args) < 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2")
	}

	startKey := args[0]
	endKey := args[1]

	resultsIterator, err := stub.GetStateByRange(startKey, endKey)
	if err != nil {
		return shim.Error(err.Error())
	}
	defer resultsIterator.Close()

	buffer, err := constructQueryResponseFromIterator(resultsIterator)
	if err != nil {
		return shim.Error(err.Error())
	}

	fmt.Printf("- getOrdersByRange queryResult:\n%s\n", buffer.String())

	return shim.Success(buffer.Bytes())
}

func (t *Chaincode) readOrderPrivateDetails(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	var name, jsonResp string
	var err error

	if len(args) != 1 {
		return shim.Error("Incorrect number of arguments. Expecting name of the order to query")
	}

	name = args[0]
	valAsbytes, err := stub.GetPrivateData("collectionMaterialOrderPrivateDetails", name) //get the order private details from chaincode state
	if err != nil {
		jsonResp = "{\"Error\":\"Failed to get private details for " + name + ": " + err.Error() + "\"}"
		return shim.Error(jsonResp)
	} else if valAsbytes == nil {
		jsonResp = "{\"Error\":\"order private details does not exist: " + name + "\"}"
		return shim.Error(jsonResp)
	}

	return shim.Success(valAsbytes)
}

func (t *Chaincode) changeOrderPrivateDetails(stub shim.ChaincodeStubInterface, args []string) pb.Response {

	if len(args) < 2 {
		return shim.Error("Incorrect number of arguments. Expecting 2")
	}

	orderName := args[0]
	newPrice := args[1]
	fmt.Println("- start changeStatus ", orderName, newPrice)

	orderAsBytes, err := stub.GetPrivateData("collectionMaterialOrderPrivateDetails", orderName)
	if err != nil {
		return shim.Error("Failed to get order:" + err.Error())
	} else if orderAsBytes == nil {
		return shim.Error("Order does not exist")
	}

	priceToChange := orderPrivateDetails{}
	err = json.Unmarshal(orderAsBytes, &priceToChange)
	if err != nil {
		return shim.Error(err.Error())
	}
	priceToChange.Price = newPrice

	orderJSONasBytes, _ := json.Marshal(priceToChange)
	err = stub.PutPrivateData("collectionMaterialOrderPrivateDetails", orderName, orderJSONasBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	fmt.Println("- end changeStatus (success)")
	return shim.Success(nil)
}
*/

func saveHealthReport(c echo.Context) error {
	report := HealthReport{}
	report.CreatedAt = time.Now()
	report.UserId = c.Get("UserId").(string)
	if err := c.Bind(&report); err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}
	db := env.MDB

	rpt := HealthReport{}
	opts := options.FindOne().SetSort(bson.D{{"created_at", 1}})
	if e := db.Collection("HealthReport").FindOne(context.Background(), bson.M{"userid": report.UserId}, opts).Decode(&rpt); e != nil {
	}
	if rpt.UserId != "" {
		report.PreviousNode = rpt.ID
	}

	report.ID = primitive.NewObjectID().Hex()
	_, err := db.Collection("HealthReport").InsertOne(context.Background(), report)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, err.Error())
	} else {
		return c.JSON(http.StatusOK, report)
	}
}

func getReportByUser(c echo.Context) error {
	report := HealthReport{}
	userId := c.Get("UserId").(string)
	db := env.MDB

	opts := options.FindOne().SetSort(bson.D{{"created_at", 1}})
	if err := db.Collection("HealthReport").FindOne(context.Background(), bson.M{"userid": userId}, opts).Decode(&report); err != nil {
	}
	return c.JSON(http.StatusOK, report)
}

func getJWT(c echo.Context) error {
	iskeyfile := false
	claims := make(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix()
	claims["UserId"] = "XCDas4e34567"

	if iskeyfile {
		content, err := ioutil.ReadFile("secret")
		if err != nil {
			fmt.Println(err)
		}
		key, err := jwt.ParseRSAPrivateKeyFromPEM(content)
		if err != nil {
			fmt.Println(err)
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)

		if err != nil {
			return c.JSON(http.StatusOK, err)
		} else {
			return c.JSON(http.StatusOK, token)
		}

	} else {

		jwt := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		token, err := jwt.SignedString([]byte("secret"))
		if err != nil {
			return c.JSON(http.StatusOK, err)
		} else {
			return c.JSON(http.StatusOK, token)
		}
	}
}

func getReportByNode(c echo.Context) error {
	id := c.QueryParam("node")

	report := HealthReport{}
	db := env.MDB
	if err := db.Collection("HealthReport").FindOne(context.Background(), bson.M{"_id": id}).Decode(&report); err != nil {
	}
	return c.JSON(http.StatusOK, report)
}
