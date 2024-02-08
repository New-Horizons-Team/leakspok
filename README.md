# leakspok

![Go Report Card](https://goreportcard.com/badge/github.com/New-Horizons-Team/leakspok)
![Build Status](https://travis-ci.com/New-Horizons-Team//leakspok.svg?branch=main)

**leakspok** is an open-source library written in Go, inspired in [pii](https://github.com/gen0cide/pii), designed to detect Personally Identifiable Information (PII) in strings. It helps developers ensure data privacy and compliance by spotting potential information leaks.
<img src="https://images.squarespace-cdn.com/content/v1/594454ad1b631b13a9131210/1616175553712-LZRWHZ0L4I2F82UH3WTS/spock1.jpg" width="200px" height="150px">

## Features

- Detect various PII types including:
    - Banking Info
    - Brazilian CNPJ, CPF, and cellphone numbers
    - Credit Card numbers
    - Email Addresses
    - IP Addresses
    - Phone Numbers
    - SSN (Social Security Numbers)
    - Street Addresses
    - UUIDs
    - VIN (Vehicle Identification Numbers)

## Installation

To install leakspok, use `go get`:

```
go get github.com/New-Horizons-Team/leakspok
```

## Usage

Here's a simple example to use leakspok:

```go
package main

import (
	"fmt"
	"github.com/New-Horizons-Team/leakspok"
)

func main() {
    text := []{"My email is john.doe@example.com", "my sensible pii"}
	t := leakspok.NewDefaultStringTester()
	result, err := t.Find(text)
    }

	// Error handling
	...

    // Print result
	fmt.Println("result: %v", result)

}
```

## Contributing

1. Fork the repository on GitHub.
2. Clone the forked repository to your machine.
3. Create a new branch.
4. Make your changes and write tests when practical.
5. Commit changes to the branch.
6. Push changes to your fork.
7. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
