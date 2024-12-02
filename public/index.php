<?php
use \psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';
require_once 'db.php';

$app = new \Slim\App;

// User Registration
$app->post('/user/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody());
    $usr = $data->username;
    $pass = $data->password;

    // Get database connection
    $database = new Database();
    $conn = $database->getConnection();

    try {
        // Check if the user already exists
        $sql = "SELECT * FROM users WHERE username = ?";
        $stmt = $conn->prepare($sql);
        $stmt->execute([$usr]);
        $data = $stmt->fetchAll();

        if (count($data) > 0) {
            // If user exists, return an error message
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => ["title" => "Username already exists"]
            ]));
        } else {
            // If user does not exist, insert new user
            $sql = "INSERT INTO users (username, password, role_id) VALUES (?, ?, ?)";
            $stmt = $conn->prepare($sql);
            $hashedPassword = hash('sha256', $pass);
            $role_id = 2; // Assuming 2 is the role ID for regular users
            $stmt->execute([$usr, $hashedPassword, $role_id]);

            // Return success response
            $response->getBody()->write(json_encode(["status" => "success", "data" => null]));
        }
    } catch (PDOException $e) {
        // Return error message on exception
        $response->getBody()->write(json_encode([
            "status" => "fail",
            "data" => ["title" => $e->getMessage()]
        ]));
    }

    return $response;
});

// Admin Registration
$app->post('/admin/register', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody(), true);
    $usr = $data['username'] ?? null;
    $pass = $data['password'] ?? null;

    // Get database connection
    $database = new Database();
    $conn = $database->getConnection();

    if (!$usr || !$pass) {
        $response->getBody()->write(json_encode([
            'status' => 'fail',
            'data' => ['title' => 'Invalid input']
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

    try {
        // Check if the user already exists
        $sql = "SELECT * FROM users WHERE username = ?";
        $stmt = $conn->prepare($sql);
        $stmt->execute([$usr]);
        $data = $stmt->fetchAll();

        if (count($data) > 0) {
            $response->getBody()->write(json_encode([
                "status" => "fail",
                "data" => ["title" => "Username already exists"]
            ]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        } else {
            // If user does not exist, insert new user with role_id 2 (regular user)
            $sql = "INSERT INTO users (username, password, role_id) VALUES (?, ?, ?)";
            $stmt = $conn->prepare($sql);
            $hashedPassword = hash('sha256', $pass);
            $role_id = 1; // Regular user role
            $stmt->execute([$usr, $hashedPassword, $role_id]);

            // Return success response
            $response->getBody()->write(json_encode([
                "status" => "success",
                "data" => null
            ]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
        }

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode([
            'status' => 'fail',
            'data' => ['title' => 'Error: ' . $e->getMessage()]
        ]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(500);
    }
});

//user authentication
$app->post('/user/authenticate', function (Request $request, Response $response, array $args) {
    $data = json_decode($request->getBody(), true);
    $usr = $data['username'] ?? null;
    $pass = $data['password'] ?? null;

    if (!$usr || !$pass) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Invalid input"]]));
        return $response->withStatus(400);
    }

    // Initialize the database connection
    $database = new Database();
    $conn = $database->getConnection();

    try {
        // SQL query to get user details including role
        $sql = "SELECT * FROM users WHERE username = :username";
        $stmt = $conn->prepare($sql);
        $stmt->execute([':username' => $usr]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            // Check the hashed password
            $hashedPass = hash('sha256', $pass);
            if ($user['password'] === $hashedPass) {
                $key = 'server_hack'; // Secret key
                $iat = time(); // Issued at
                $exp = $iat + 3600; // Expiry time (1 hour)
                $payload = [
                    'iss' => 'https://library.org',
                    'aud' => 'https://library.org',
                    'iat' => $iat,
                    'exp' => $exp,
                    'role' => $user['role_id'], // Add role in the payload
                    "data" => [
                        "userid" => $user['userid']
                    ]
                ];
                $jwt = JWT::encode($payload, $key, 'HS256');

                // Set token in cookies
                setcookie(
                    'auth_token', 
                    $jwt, 
                    $exp, 
                    '/',  // Path
                    '',   // Domain (leave empty for current domain)
                    false, // Secure (set to true if using HTTPS)
                    true,  // HttpOnly (prevent access via JavaScript)
                );

                $response->getBody()->write(json_encode(["status" => "success", "message" => "Authentication successful."]));
                return $response;
            } else {
                $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "Invalid password"]]));
                return $response->withStatus(401);
            }
        } else {
            $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => "User not found"]]));
            return $response->withStatus(404);
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["status" => "fail", "data" => ["title" => $e->getMessage()]]));
        return $response->withStatus(500);
    }
});




$app->put('/user/update', function (Request $request, Response $response, array $args) {
    $authHeader = $request->getHeader('Authorization');

    if (!$authHeader) {
        return $response->withStatus(401)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "No token provided"))));
    }

    $jwt = str_replace('Bearer ', '', $authHeader[0]);
    $key = 'server_hack';

    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }

    // Check if token is present in the session
    if (!isset($_SESSION['token']) || $_SESSION['token']['token'] !== $jwt) {
        return $response->withStatus(401)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    // Check if the token has already been used
    if ($_SESSION['token']['is_used']) {
        return $response->withStatus(401)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Token has already been used"))));
    }

    try {
        // Decode the JWT
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Get request data (new username and password)
        $data = json_decode($request->getBody());
        $newUsername = $data->username;
        $newPassword = $data->password;

        if (!isset($decoded->data->userid)) {
            return $response->withStatus(401)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid token"))));
        }

        $userid = $decoded->data->userid;

        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "cabatingan_library";

        try {
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Check if the new username already exists
            $checkSql = "SELECT * FROM users WHERE username = '" . $newUsername . "' AND userid != '" . $userid . "'";
            $checkStmt = $conn->query($checkSql);
            $existingUser = $checkStmt->fetchAll();

            if (count($existingUser) > 0) {
                return $response->withStatus(409)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Username already exists"))));
            }

            // Update the user data
            $updateSql = "UPDATE users SET username = '" . $newUsername . "', password = '" . hash('SHA256', $newPassword) . "' WHERE userid = '" . $userid . "'";
            $conn->exec($updateSql);

            // Mark token as used
            $_SESSION['token']['is_used'] = true;

            // Generate a new token
            $iat = time();
            $newPayload = [
                'iss' => 'https://library.org',
                'aud' => 'https://library.org',
                'iat' => $iat,
                'exp' => $iat + 3600,  // New token expiration
                "data" => [
                    "userid" => $userid
                ]
            ];
            $newJwt = JWT::encode($newPayload, $key, 'HS256');

            // Store the new token in the session
            $_SESSION['token'] = [
                'token' => $newJwt,
                'is_used' => false,
                'expires_at' => $iat + 3600
            ];

            // Return success with the new token
            $response->getBody()->write(json_encode(array("status" => "success", "new_token" => $newJwt, "data" => null)));
        } catch (PDOException $e) {
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
        }
    } catch (Exception $e) {
        $response->withStatus(401)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Token validation failed", "error" => $e->getMessage()))));
    }

    return $response;
});

// Add a new book
$app->post('/books/add', function (Request $request, Response $response, array $args) {
    // Get the Authorization header
    $authHeader = $request->getHeader('Authorization');
    
    if (!$authHeader) {
        return $response->withStatus(401)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "No token provided"))));
    }
    
    $jwt = str_replace('Bearer ', '', $authHeader[0]);
    $key = 'server_hack';

    // Start the session
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }

    // Check if token is present in the session
    if (!isset($_SESSION['token']) || $_SESSION['token']['token'] !== $jwt) {
        return $response->withStatus(401)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    // Check if the token has already been used
    if ($_SESSION['token']['is_used']) {
        return $response->withStatus(401)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Token has already been used"))));
    }

    try {
        // Decode the JWT
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Get request data (book title and authors)
        $data = json_decode($request->getBody());
        $title = $data->title;
        $authors = $data->authors; // Expecting an array of author names

        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "cabatingan_library";

        try {
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Start transaction
            $conn->beginTransaction();

            // Insert the book title using string concatenation
            $insertBookSql = "INSERT INTO books (title) VALUES ('" . $title . "')";
            $conn->exec($insertBookSql);
            $bookId = $conn->lastInsertId(); // Get the last inserted book ID

            // Loop through authors and insert them if they do not exist
            foreach ($authors as $authorName) {
                // Check if the author already exists using string concatenation
                $checkAuthorSql = "SELECT authorid FROM authors WHERE name = '" . $authorName . "'";
                $checkStmt = $conn->query($checkAuthorSql);
                $authorData = $checkStmt->fetch(PDO::FETCH_ASSOC);

                if ($authorData) {
                    // Author exists, get the author ID
                    $authorId = $authorData['authorid'];
                } else {
                    // Author does not exist, insert new author using string concatenation
                    $insertAuthorSql = "INSERT INTO authors (name) VALUES ('" . $authorName . "')";
                    $conn->exec($insertAuthorSql);
                    $authorId = $conn->lastInsertId(); // Get the last inserted author ID
                }

                // Insert into book_authors junction table using string concatenation
                $insertBookAuthorSql = "INSERT INTO book_authors (bookid, authorid) VALUES ('" . $bookId . "', '" . $authorId . "')";
                $conn->exec($insertBookAuthorSql);
            }

            // Commit the transaction
            $conn->commit();

            // Mark token as used
            $_SESSION['token']['is_used'] = true;

            // Generate a new token
            $iat = time();
            $newPayload = [
                'iss' => 'https://library.org',
                'aud' => 'https://library.org',
                'iat' => $iat,
                'exp' => $iat + 3600,  // New token expiration
                "data" => [
                    "userid" => $decoded->data->userid // Pass the same userid or modify as needed
                ]
            ];
            $newJwt = JWT::encode($newPayload, $key, 'HS256');

            // Store the new token in the session
            $_SESSION['token'] = [
                'token' => $newJwt,
                'is_used' => false,
                'expires_at' => $iat + 3600
            ];

            // Return success with the new token
            $response->getBody()->write(json_encode(array("status" => "success", "new_token" => $newJwt, "data" => array("bookid" => $bookId))));
        } catch (PDOException $e) {
            // Rollback transaction if something went wrong
            $conn->rollBack();
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
        }
    } catch (Exception $e) {
        $response->withStatus(401)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Token validation failed", "error" => $e->getMessage()))));
    }

    return $response;
});


$app->put('/books/update', function (Request $request, Response $response, array $args) {
    $authHeader = $request->getHeader('Authorization');

    if (!$authHeader) {
        return $response->withStatus(401)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "No token provided"))));
    }

    $jwt = str_replace('Bearer ', '', $authHeader[0]);
    $key = 'server_hack';

    // Start the session
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }

    // Check if token is present in the session
    if (!isset($_SESSION['token']) || $_SESSION['token']['token'] !== $jwt) {
        return $response->withStatus(401)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    // Check if the token has already been used
    if ($_SESSION['token']['is_used']) {
        return $response->withStatus(401)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Token has already been used"))));
    }

    try {
        // Decode the JWT
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Get request data (book ID, new title, and authors)
        $data = json_decode($request->getBody());
        $bookId = $data->bookId; // Get the book ID from the payload
        $newTitle = $data->title;
        $authors = $data->authors; // Expecting an array of author names

        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "cabatingan_library";

        try {
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Start transaction
            $conn->beginTransaction();

            // Update the book title
            $updateBookSql = "UPDATE books SET title = '" . $newTitle . "' WHERE bookid = '" . $bookId . "'";
            $conn->exec($updateBookSql);

            // Clear existing authors for the book
            $deleteAuthorsSql = "DELETE FROM book_authors WHERE bookid = '" . $bookId . "'";
            $conn->exec($deleteAuthorsSql);

            // Loop through authors and insert them if they do not exist
            foreach ($authors as $authorName) {
                // Check if the author already exists
                $checkAuthorSql = "SELECT authorid FROM authors WHERE name = '" . $authorName . "'";
                $checkStmt = $conn->query($checkAuthorSql);
                $authorData = $checkStmt->fetch(PDO::FETCH_ASSOC);

                if ($authorData) {
                    // Author exists, get the author ID
                    $authorId = $authorData['authorid'];
                } else {
                    // Author does not exist, insert new author
                    $insertAuthorSql = "INSERT INTO authors (name) VALUES ('" . $authorName . "')";
                    $conn->exec($insertAuthorSql);
                    $authorId = $conn->lastInsertId(); // Get the last inserted author ID
                }

                // Insert into book_authors junction table
                $insertBookAuthorSql = "INSERT INTO book_authors (bookid, authorid) VALUES ('" . $bookId . "', '" . $authorId . "')";
                $conn->exec($insertBookAuthorSql);
            }

            // Commit the transaction
            $conn->commit();

            // Mark token as used
            $_SESSION['token']['is_used'] = true;

            // Generate a new token
            $iat = time();
            $newPayload = [
                'iss' => 'https://library.org',
                'aud' => 'https://library.org',
                'iat' => $iat,
                'exp' => $iat + 3600, // New token expiration
                "data" => [
                    "userid" => $decoded->data->userid // Pass the same userid or modify as needed
                ]
            ];
            $newJwt = JWT::encode($newPayload, $key, 'HS256');

            // Store the new token in the session
            $_SESSION['token'] = [
                'token' => $newJwt,
                'is_used' => false,
                'expires_at' => $iat + 3600
            ];

            // Return success with the new token
            $response->getBody()->write(json_encode(array("status" => "success", "new_token" => $newJwt, "data" => array("bookid" => $bookId))));
        } catch (PDOException $e) {
            // Rollback transaction if something went wrong
            $conn->rollBack();
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
        }
    } catch (Exception $e) {
        $response->withStatus(401)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Token validation failed", "error" => $e->getMessage()))));
    }

    return $response;
});


$app->delete('/books/delete', function (Request $request, Response $response, array $args) {
    $authHeader = $request->getHeader('Authorization');

    if (!$authHeader) {
        return $response->withStatus(401)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "No token provided"))));
    }

    $jwt = str_replace('Bearer ', '', $authHeader[0]);
    $key = 'server_hack';

    // Start the session
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }

    // Check if token is present in the session
    if (!isset($_SESSION['token']) || $_SESSION['token']['token'] !== $jwt) {
        return $response->withStatus(401)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Invalid or expired token"))));
    }

    // Check if the token has already been used
    if ($_SESSION['token']['is_used']) {
        return $response->withStatus(401)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Token has already been used"))));
    }

    try {
        // Decode the JWT
        $decoded = JWT::decode($jwt, new Key($key, 'HS256'));

        // Get request data (book ID)
        $data = json_decode($request->getBody());
        $bookId = $data->bookId; // Get the book ID from the payload

        $servername = "localhost";
        $username = "root";
        $password = "";
        $dbname = "cabatingan_library";

        try {
            $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
            $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

            // Start transaction
            $conn->beginTransaction();

            // Delete from book_authors junction table
            $deleteBookAuthorsSql = "DELETE FROM book_authors WHERE bookid = '" . $bookId . "'";
            $conn->exec($deleteBookAuthorsSql);

            // Delete the book
            $deleteBookSql = "DELETE FROM books WHERE bookid = '" . $bookId . "'";
            $conn->exec($deleteBookSql);

            // Commit the transaction
            $conn->commit();

            // Mark token as used
            $_SESSION['token']['is_used'] = true;

            // Generate a new token
            $iat = time();
            $newPayload = [
                'iss' => 'https://library.org',
                'aud' => 'https://library.org',
                'iat' => $iat,
                'exp' => $iat + 3600, // New token expiration
                "data" => [
                    "userid" => $decoded->data->userid // Pass the same userid or modify as needed
                ]
            ];
            $newJwt = JWT::encode($newPayload, $key, 'HS256');

            // Store the new token in the session
            $_SESSION['token'] = [
                'token' => $newJwt,
                'is_used' => false,
                'expires_at' => $iat + 3600
            ];

            // Return success with the new token
            $response->getBody()->write(json_encode(array("status" => "success", "new_token" => $newJwt, "data" => array("message" => "Book deleted successfully"))));
        } catch (PDOException $e) {
            // Rollback transaction if something went wrong
            $conn->rollBack();
            $response->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => $e->getMessage()))));
        }
    } catch (Exception $e) {
        $response->withStatus(401)->getBody()->write(json_encode(array("status" => "fail", "data" => array("title" => "Token validation failed", "error" => $e->getMessage()))));
    }

    return $response;
});




$app->run();
?>