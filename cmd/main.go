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
	"golang.org/x/crypto/bcrypt"
)

type Person struct {
	PersonUuid     string `json:"person_uuid,omitempty"`
	ProfilePicture string `json:"profile_picture,omitempty"`
	FirstName      string `json:"first_name,omitempty"`
	MiddleName     string `json:"middle_name,omitempty"`
	LastName       string `json:"last_name,omitempty"`
	Email          string `json:"email,omitempty"`
	Password       string `json:"password,omitempty"`
	MobileNumber   string `json:"mobile_number,omitempty"`
	Gender         string `json:"gender,omitempty"`
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

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPerson.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}

		newPerson.Password = string(hashedPassword)

		newPersonUUID, err := addNewPersonToDirectus(newPerson)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, gin.H{`message`: `Person created successfully: ` + newPersonUUID})
	})

	router.POST("/login", func(c *gin.Context) {
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

		// fmt.Println(req.Email)
		if person == nil || person.Email == "" || person.Password == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "No such user or incomplete data"})
			return
		}

		// Compare the provided password with the hashed password from the database
		// Assuming person.Password contains the hashed password retrieved from the database
		err = bcrypt.CompareHashAndPassword([]byte(person.Password), []byte(req.Password))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Login successful", "person_data": person})
	})

	router.GET("/home/:id", func(c *gin.Context) {
		var person *Person
		id := c.Param("id")
		if id == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Person ID is required"})
			return
		}
		// fmt.Println(id, "this is id")

		person, err := findPersonByUUID(id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// fmt.Println(person, "this is person found by id")

		if person == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Person not found"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"person_data": person})
	})

	router.PATCH("/home/:id", func(c *gin.Context) {
		id := c.Param("id")
		if id == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error: ID": "Person ID is required"})
			return
		}

		var updates Person
		if err := c.ShouldBindJSON(&updates); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error: binding": "Invalid request body"})
			return
		}

		// Fetch the existing data
		existingPerson, err := findPersonByUUID(id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error: existingPerson": err.Error()})
			return
		}
		if existingPerson == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Person not found"})
			return
		}

		// Update fields if provided
		if updates.ProfilePicture != "" {
			existingPerson.ProfilePicture = updates.ProfilePicture
		}
		if updates.FirstName != "" {
			existingPerson.FirstName = updates.FirstName
		}
		if updates.MiddleName != "" {
			existingPerson.MiddleName = updates.MiddleName
		}
		if updates.LastName != "" {
			existingPerson.LastName = updates.LastName
		}
		if updates.Email != "" {
			existingPerson.Email = updates.Email
		}
		if updates.Password != "" {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(updates.Password), bcrypt.DefaultCost)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
				return
			}
			existingPerson.Password = string(hashedPassword)
		}
		if updates.MobileNumber != "" {
			existingPerson.MobileNumber = updates.MobileNumber
		}
		if updates.Gender != "" {
			existingPerson.Gender = updates.Gender
		}

		// fmt.Println(existingPerson)
		// Save updated data
		updatedUUID, updateErr := updatePerson(existingPerson)
		if updateErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error: updateUUID": updateErr.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Person updated successfully", "person_uuid": updatedUUID})

	})

	router.Run() // By default, it listens on :8080
}

func generateUUID() string {
	return uuid.New().String()
}

func addNewPersonToDirectus(newPerson Person) (string, error) {
	newPerson.PersonUuid = generateUUID()

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
	req.Header.Set("Authorization", "Bearer SunZsR_2wQjHGgm_HeU1NW6KnXD-FJCm")

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

	return newPerson.PersonUuid, nil
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
	req.Header.Add("Authorization", "Bearer SunZsR_2wQjHGgm_HeU1NW6KnXD-FJCm")

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

func findPersonByUUID(id string) (*Person, error) {
	var response struct {
		Data []Person `json:"data"`
	}

	// Set up the Directus API endpoint and parameters
	baseURL := "https://cdp.apcwo.org/items/person"
	params := url.Values{}
	params.Add("filter[person_uuid][_eq]", id) // Consider using "_eq" for exact matches
	fullURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

	// Make a request to Directus
	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, err
	}

	// Include your API access token here
	req.Header.Add("Authorization", "Bearer SunZsR_2wQjHGgm_HeU1NW6KnXD-FJCm")

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

func updatePerson(person *Person) (string, error) {
	personJSON, err := json.Marshal(person)
	if err != nil {
		return "", err
	}

	url := "https://cdp.apcwo.org/items/person/" + person.PersonUuid
	// fmt.Println(string(url))
	req, err := http.NewRequest("PATCH", url, bytes.NewBuffer(personJSON))
	if err != nil {
		return "", err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer SunZsR_2wQjHGgm_HeU1NW6KnXD-FJCm")
	// fmt.Println(req)
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	// fmt.Println(res)
	if res.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			fmt.Println("Error reading response body:", err)
			return "", err
		}
		bodyString := string(bodyBytes)
		// fmt.Println("API response error:", bodyString)
		return "", fmt.Errorf("failed to update person: %s", bodyString)
	}

	return person.PersonUuid, nil
}
