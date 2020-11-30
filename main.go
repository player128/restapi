package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

// Глобальный секретный ключ
var mySigningKey = []byte("secret")

type User struct {
	GUID     uint16 `json:"GUID"`
	Login    string `json:"login"`
	Password string `json:"password"`
	Admin    string `json:"admin"`
}

type Session struct {
	GUID         uint16 `json:"GUID"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

func main() {
	router := mux.NewRouter()

	router.HandleFunc("/login", LoginPage).Methods("POST")
	router.HandleFunc("/refresh", Refresh).Methods("POST")
	router.HandleFunc("/delete", Delete).Methods("POST")
	router.HandleFunc("/deleteall", DeleteAll).Methods("POST")
	http.ListenAndServe(":8000", router)
}

type PairToken struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type RefreshObj struct {
	Exp  string `json:"exp"`
	GUID int    `json:"GUID"`
}

func CreateToken(u *User) PairToken {
	var pairToken PairToken
	accessToken := jwt.New(jwt.SigningMethodHS512)
	aclaims := accessToken.Claims.(jwt.MapClaims)
	// // Устанавливаем набор параметров для токена
	aclaims["admin"] = u.Admin
	aclaims["name"] = u.Login
	aclaims["GUID"] = u.GUID
	aclaims["exp"] = time.Now().Add(time.Minute * 10).Unix()
	// // Подписываем токен нашим секретным ключем
	atokenString, _ := accessToken.SignedString(mySigningKey)
	exp := time.Now().Add(time.Hour * 24).Unix()
	rtokenString := `{"exp":"` + strconv.Itoa(int(exp)) + `","GUID":` + strconv.Itoa(int(u.GUID)) + `}`
	encodedString := base64.URLEncoding.EncodeToString([]byte(rtokenString))
	pairToken.AccessToken = atokenString
	pairToken.RefreshToken = encodedString
	return pairToken
}

func Delete(w http.ResponseWriter, r *http.Request) {

	var Tokens string = ""

	for _, cookie := range r.Cookies() {
		if cookie.Name == "Slava" {
			Tokens = cookie.Value
		}
	}

	if Tokens == "" || Tokens == "None" {
		w.Write([]byte("У вас нет токена!"))
		return
	}

	arrattoken := strings.Split(Tokens, ",")

	if len(arrattoken) == 2 {
		fmt.Println(arrattoken[1])

		var refreshObj RefreshObj
		refreshstring, _ := base64.URLEncoding.DecodeString(arrattoken[1])
		err := json.Unmarshal([]byte(refreshstring), &refreshObj)

		fmt.Println(refreshstring)
		if err != nil {
			fmt.Println(err)
			return
		}

		// Set client options
		clientOptions := options.Client().ApplyURI("mongodb://localhost:27018")

		// Connect to MongoDB
		client, err := mongo.Connect(context.TODO(), clientOptions)

		if err != nil {
			log.Fatal(err)
		}

		// Check the connection
		err = client.Ping(context.TODO(), nil)

		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Connected to MongoDB!")

		db := client.Database("server")
		collectionTwo := db.Collection("session")

		var result2 Session

		err = collectionTwo.FindOne(context.TODO(), bson.M{"accesstoken": arrattoken[0]}).Decode(&result2)
		if err != nil {
			//log.Fatal(err)
			fmt.Printf(err.Error())
			return
		}

		if !CheckTokenHash(arrattoken[1], result2.RefreshToken) {
			fmt.Print("Токены не совпали")
			return
		}

		// transaction //sessionContext
		err = db.Client().UseSession(context.TODO(), func(sessionContext mongo.SessionContext) error {
			err := sessionContext.StartTransaction()

			deleteresult, err := collectionTwo.DeleteOne(sessionContext, bson.M{"refreshtoken": result2.RefreshToken})
			if err != nil {
				//log.Fatal(err)
				sessionContext.AbortTransaction(sessionContext)
				fmt.Printf(err.Error())
				return err
			} else {
				fmt.Print("Удалено:")
				fmt.Print(deleteresult.DeletedCount)
				sessionContext.CommitTransaction(sessionContext)
			}
			return nil
		})

		if err != nil {
			fmt.Println(err)
			return
		}

		err = client.Disconnect(context.TODO())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Connection to MongoDB closed.")
		cookie := http.Cookie{Name: "Slava", Value: "None"}
		http.SetCookie(w, &cookie)
	}
}

func DeleteAll(w http.ResponseWriter, r *http.Request) {

	var Tokens string = ""

	for _, cookie := range r.Cookies() {
		if cookie.Name == "Slava" {
			Tokens = cookie.Value
		}
	}

	if Tokens == "" || Tokens == "None" {
		w.Write([]byte("У вас нет токена!"))
		return
	}

	arrattoken := strings.Split(Tokens, ",")

	if len(arrattoken) == 2 {
		fmt.Println(arrattoken[1])

		var refreshObj RefreshObj
		refreshstring, _ := base64.URLEncoding.DecodeString(arrattoken[1])
		err := json.Unmarshal([]byte(refreshstring), &refreshObj)

		fmt.Println(refreshstring)
		if err != nil {
			fmt.Println(err)
			return
		}

		// Set client options
		clientOptions := options.Client().ApplyURI("mongodb://localhost:27018")

		// Connect to MongoDB
		client, err := mongo.Connect(context.TODO(), clientOptions)

		if err != nil {
			log.Fatal(err)
		}

		// Check the connection
		err = client.Ping(context.TODO(), nil)

		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Connected to MongoDB!")

		db := client.Database("server")
		collectionTwo := db.Collection("session")

		var result2 Session

		err = collectionTwo.FindOne(context.TODO(), bson.M{"accesstoken": arrattoken[0]}).Decode(&result2)
		if err != nil {
			//log.Fatal(err)
			fmt.Printf(err.Error())
			return
		}

		if !CheckTokenHash(arrattoken[1], result2.RefreshToken) {
			fmt.Print("Токены не совпали")
			return
		}

		// transaction //sessionContext
		err = db.Client().UseSession(context.TODO(), func(sessionContext mongo.SessionContext) error {
			err := sessionContext.StartTransaction()

			deleteresult, err := collectionTwo.DeleteMany(sessionContext, bson.M{"guid": result2.GUID})
			if err != nil {
				//log.Fatal(err)
				sessionContext.AbortTransaction(sessionContext)
				fmt.Printf(err.Error())
				return err
			} else {
				fmt.Print("Удалено:")
				fmt.Print(deleteresult.DeletedCount)
				fmt.Print(" токенов")
				sessionContext.CommitTransaction(sessionContext)
			}
			return nil
		})

		if err != nil {
			fmt.Println(err)
			return
		}

		err = client.Disconnect(context.TODO())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Connection to MongoDB closed.")

		cookie := http.Cookie{Name: "Slava", Value: "None"}
		http.SetCookie(w, &cookie)
	}
}

func LoginPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// var Tokens string = ""

	// for _, cookie := range r.Cookies() {
	// 	if cookie.Name == "Slava" {
	// 		Tokens = cookie.Value
	// 	}
	// }

	// if Tokens != "" && Tokens != "None" {
	// 	w.Write([]byte("У вас уже есть токен"))
	// 	return
	// }

	var user User
	_ = json.NewDecoder(r.Body).Decode(&user)

	// Set client options
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27018")

	// Connect to MongoDB
	client, err := mongo.Connect(context.TODO(), clientOptions)

	if err != nil {
		log.Fatal(err)
	}

	// Check the connection
	err = client.Ping(context.TODO(), nil)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB!")

	db := client.Database("server")
	collectionTwo := db.Collection("session")
	collection := db.Collection("account")

	var result User

	err = collection.FindOne(context.TODO(), bson.M{"Login": user.Login, "Password": user.Password}).Decode(&result)
	if err != nil {
		//log.Fatal(err)
		fmt.Println(err.Error())
		return
	}

	pairToken := CreateToken(&result)
	// // Создаем новый токен
	var session Session

	session.GUID = result.GUID
	session.AccessToken = pairToken.AccessToken

	RefreshToken := []byte(pairToken.RefreshToken)
	hashedToken, err := bcrypt.GenerateFromPassword(RefreshToken, bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}

	session.RefreshToken = string(hashedToken)
	///////////////////////////////////////////////////////////
	err = db.Client().UseSession(context.TODO(), func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()

		insertResult, err := collectionTwo.InsertOne(sessionContext, session)
		if err != nil {
			sessionContext.AbortTransaction(sessionContext)
			fmt.Printf(err.Error())
			return err
		} else {
			sessionContext.CommitTransaction(sessionContext)
			fmt.Println(insertResult)
		}
		return nil
	})

	if err != nil {
		fmt.Println(err)
		return
	}
	///////////////////////////////////////////////////////////
	fmt.Printf("Found a single document: %+v\n", result)
	err = client.Disconnect(context.TODO())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connection to MongoDB closed.")
	tokenss := pairToken.AccessToken + "," + pairToken.RefreshToken

	expiration := time.Now().Add(time.Hour * 24 * 365)
	cookie := http.Cookie{Name: "Slava", Value: tokenss, Expires: expiration}
	http.SetCookie(w, &cookie)
}

func CheckTokenHash(token, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(token))
	return err == nil
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	var Tokens string = ""

	for _, cookie := range r.Cookies() {
		if cookie.Name == "Slava" {
			Tokens = cookie.Value
		}
	}

	if Tokens == "" || Tokens == "None" {
		w.Write([]byte("У вас нет токена!"))
		return
	}

	arrattoken := strings.Split(Tokens, ",")

	if len(arrattoken) == 2 {
		//fmt.Println(arrattoken[1])

		var refreshObj RefreshObj
		refreshstring, _ := base64.URLEncoding.DecodeString(arrattoken[1])
		err := json.Unmarshal([]byte(refreshstring), &refreshObj)
		//fmt.Println(refreshstring)
		if err != nil {
			fmt.Println(err)
			return
		}

		// fmt.Println(refreshObj.GUID)

		// 	// Set client options
		clientOptions := options.Client().ApplyURI("mongodb://localhost:27018")

		// Connect to MongoDB
		client, err := mongo.Connect(context.TODO(), clientOptions)

		if err != nil {
			log.Fatal(err)
		}

		// Check the connection
		err = client.Ping(context.TODO(), nil)

		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Connected to MongoDB!")

		db := client.Database("server")
		collectionTwo := db.Collection("session")
		collection := db.Collection("account")

		var result2 Session

		err = collectionTwo.FindOne(context.TODO(), bson.M{"accesstoken": arrattoken[0]}).Decode(&result2)
		if err != nil {
			//log.Fatal(err)
			fmt.Printf(err.Error())
			return
		}

		if !CheckTokenHash(arrattoken[1], result2.RefreshToken) {
			fmt.Print("Токены не совпали")
			return
		}
		////////////////////////////////////////////
		// transaction //sessionContext
		err = db.Client().UseSession(context.TODO(), func(sessionContext mongo.SessionContext) error {
			err := sessionContext.StartTransaction()

			deleteresult, err := collectionTwo.DeleteOne(sessionContext, bson.M{"refreshtoken": result2.RefreshToken})
			if err != nil {
				//log.Fatal(err)
				sessionContext.AbortTransaction(sessionContext)
				fmt.Printf(err.Error())
				return err
			} else {
				fmt.Print("Удалено:")
				fmt.Print(deleteresult.DeletedCount)
				sessionContext.CommitTransaction(sessionContext)
			}
			return nil
		})

		if err != nil {
			fmt.Println(err)
			return
		}
		/////////////////////////////////////////////////////
		var result User

		err = collection.FindOne(context.TODO(), bson.M{"GUID": refreshObj.GUID}).Decode(&result)
		if err != nil {
			//log.Fatal(err)
			fmt.Printf(err.Error())
			return
		}

		pairToken := CreateToken(&result)
		// // Создаем новый токен
		var session Session

		session.GUID = result.GUID
		session.AccessToken = pairToken.AccessToken

		RefreshToken := []byte(pairToken.RefreshToken)
		hashedToken, err := bcrypt.GenerateFromPassword(RefreshToken, bcrypt.DefaultCost)
		if err != nil {
			panic(err)
		}
		//fmt.Println(string(hashedToken))
		session.RefreshToken = string(hashedToken)
		///////////////////////////////////////////////////////////
		err = db.Client().UseSession(context.TODO(), func(sessionContext mongo.SessionContext) error {
			err := sessionContext.StartTransaction()

			insertResult, err := collectionTwo.InsertOne(sessionContext, session)
			if err != nil {
				sessionContext.AbortTransaction(sessionContext)
				fmt.Printf(err.Error())
				return err
			} else {
				sessionContext.CommitTransaction(sessionContext)
				fmt.Println(insertResult)
			}
			return nil
		})

		if err != nil {
			fmt.Println(err)
			return
		}
		///////////////////////////////////////////////////////////

		err = client.Disconnect(context.TODO())
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Connection to MongoDB closed.")
		tokenss := pairToken.AccessToken + "," + pairToken.RefreshToken
		expiration := time.Now().Add(time.Hour * 24 * 365)
		cookie := http.Cookie{Name: "Slava", Value: tokenss, Expires: expiration}
		http.SetCookie(w, &cookie)
	}
}
