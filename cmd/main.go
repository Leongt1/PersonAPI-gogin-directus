package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	// "golang.org/x/crypto/bcrypt"
)

type Person struct {
	Person_uuid string `json:"person_uuid"`
	FirstName   string `json:"first_name" binding:"alpha"`
	LastName    string `json:"last_name" binding:"alpha"`
	Email       string `json:"email" binding:"required,email"`
	Password    string `json:"password" binding:"required,min=8"`
}

func main() {
	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"}, // Caution: Use more restrictive settings in production
		AllowMethods:     []string{"POST", "GET"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowWebSockets:  true,
	}))

	// repo := repository.NewPersonRepository()
	// handler := handler.NewHandler(repo)

	// Set up the base URL
	router.POST("/signin", func(c *gin.Context) {
		var newPerson Person

		if err := c.ShouldBindJSON(&newPerson); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPerson.Password), bcrypt.DefaultCost)
		// if err != nil {
		// 	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		// 	return
		// }

		// newPerson.Password = string(hashedPassword)

		newPersonUUID, err := addNewPersonToDirectus(newPerson)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, gin.H{`message`: `Person created successfully: ` + newPersonUUID})
	})

	router.GET("/login", func(c *gin.Context) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		person, err := findPersonByEmail(req.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if person == nil || person.Email == "" || person.Password == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No such user or incomplete data"})
			return
		}

		// // Compare the provided password with the hashed password from the database
		// err = bcrypt.CompareHashAndPassword([]byte(person.Password), []byte(req.Password))
		// if err != nil {
		// 	c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		// 	return
		// }

		c.JSON(http.StatusOK, gin.H{"message": "Login successful", "person_data": person})
	})

	router.Run() // By default, it listens on :8080
}

func generateUUID() string {
	return uuid.New().String()
}

func addNewPersonToDirectus(newPerson Person) (string, error) {
	newPerson.Person_uuid = generateUUID()

	personJSON, err := json.Marshal(newPerson)
	if err != nil {
		return "", err
	}

	url := "https://cdp.apcwo.org/items/person"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(personJSON))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer L3KdemVBEnbXd0oyFeiLOosn3NyWkyWU")

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return "", err
		}
		bodyString := string(bodyBytes)
		return "", fmt.Errorf("failed to add person: %s", bodyString)
	}

	return newPerson.Person_uuid, nil
}

func findPersonByEmail(email string) (*Person, error) {
	var response struct {
		Data []Person `json:"data"`
	}

	// Set up the Directus API endpoint and parameters
	baseURL := "https://cdp.apcwo.org/items/person"
	params := url.Values{}
	params.Add("filter[email][_eq]", email) // Consider using "_eq" for exact matches
	fullURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

	// Make a request to Directus
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, err
	}

	// Include your API access token here
	req.Header.Add("Authorization", "Bearer L3KdemVBEnbXd0oyFeiLOosn3NyWkyWU")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check the HTTP status code
	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("directus API error: %s", string(bodyBytes))
	}

	// Decode the JSON response
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	// Check if any person is returned
	if len(response.Data) == 0 {
		return nil, nil // No user found
	}

	return &response.Data[0], nil // Return the first person found
}
