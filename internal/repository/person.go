package repository

import (
	"bytes"
	"encoding/json"
	"net/http"

	"example/personapi/internal/model"
)

type PersonRepository struct {
	apiURL string
	apiKey string
}

func NewPersonRepository() *PersonRepository {
	return &PersonRepository{
		apiURL: "https://cdp.apcwo.org",            // Replace with your actual Directus instance URL
		apiKey: "L3KdemVBEnbXd0oyFeiLOosn3NyWkyWU", // Replace with your actual Directus API key
	}
}

func (r *PersonRepository) Createperson(person *model.Person) error {
	personData, err := json.Marshal(map[string]interface{}{
		"first_name":      person.FirstName,
		"last_name":       person.LastName,
		"email":           person.Email,
		"hashed_password": person.HashedPassword, // Consider handling password hashing within Directus or before this step
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", r.apiURL+"/items/person", bytes.NewBuffer(personData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return err // You might want to handle the error more gracefully
	}

	return nil
}
