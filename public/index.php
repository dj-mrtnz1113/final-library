<?php
use \psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require '../src/vendor/autoload.php';
require_once 'db.php';

$app = new \Slim\App;

header("Access-Control-Allow-Origin: *"); // Allow all origins (for testing purposes)
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

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
            $role_id = 2;
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

                // Return response with role and token
                $response->getBody()->write(json_encode([
                    "status" => "success",
                    "message" => "Authentication successful.",
                    "role" => $user['role_id'],  // Include the role in the response
                    "token" => $jwt              // Include the JWT token in the response
                ]));
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


$app->post('/admin/addbook', function (Request $request, Response $response, array $args) {
    // Step 1: Check for JWT in FormData
    $jwt = $_POST['auth_token'] ?? null;
    if (!$jwt) {
        return $response->withStatus(401)->withHeader('Content-Type', 'application/json')
            ->getBody()->write(json_encode(['status' => 'fail', 'message' => 'No token provided.']));
    }

    try {
        // Step 2: Decode JWT
        $key = new Key('server_hack', 'HS256');
        $decoded = JWT::decode($jwt, $key);

        if ($decoded->role !== 1) {
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json')
                ->getBody()->write(json_encode(['status' => 'fail', 'message' => 'Forbidden. Admins only.']));
        }

        // Step 3: Validate form data
        $title = $_POST['title'] ?? null;
        $year = $_POST['year'] ?? null;
        $authorNames = json_decode($_POST['author_name'] ?? '[]', true);

        if (!$title || !$year || !$authorNames) {
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json')
                ->getBody()->write(json_encode(['status' => 'fail', 'message' => 'Missing required fields.']));
        }

        // Step 4: Handle file upload
        if (isset($_FILES['thumbnail']) && $_FILES['thumbnail']['error'] === UPLOAD_ERR_OK) {
            $uploadDir = __DIR__ . '/uploads/';
            if (!is_dir($uploadDir)) {
                mkdir($uploadDir, 0755, true); // Create directory if not exists
            }

            $filename = basename($_FILES['thumbnail']['name']);
            $filepath = $uploadDir . $filename;

            if (!move_uploaded_file($_FILES['thumbnail']['tmp_name'], $filepath)) {
                return $response->withStatus(500)->withHeader('Content-Type', 'application/json')
                    ->getBody()->write(json_encode(['status' => 'fail', 'message' => 'Failed to upload file.']));
            }
        } else {
            return $response->withStatus(400)->withHeader('Content-Type', 'application/json')
                ->getBody()->write(json_encode(['status' => 'fail', 'message' => 'Thumbnail file is required.']));
        }

        // Step 5: Insert book and authors into the database
        $database = new Database();
        $conn = $database->getConnection();

        $sql = "INSERT INTO books (title, year, thumbnail) VALUES (?, ?, ?)";
        $stmt = $conn->prepare($sql);
        $stmt->execute([$title, $year, $filename]); // Store only the filename

        $bookid = $conn->lastInsertId();

        foreach ($authorNames as $authorName) {
            $authorStmt = $conn->prepare("SELECT authorid FROM authors WHERE name = ?");
            $authorStmt->execute([$authorName]);
            $author = $authorStmt->fetch(PDO::FETCH_ASSOC);

            if (!$author) {
                $authorInsert = "INSERT INTO authors (name) VALUES (?)";
                $stmt = $conn->prepare($authorInsert);
                $stmt->execute([$authorName]);
                $authorId = $conn->lastInsertId();
            } else {
                $authorId = $author['authorid'];
            }

            $bookAuthorInsert = "INSERT INTO book_authors (bookid, authorid) VALUES (?, ?)";
            $stmt = $conn->prepare($bookAuthorInsert);
            $stmt->execute([$bookid, $authorId]);
        }

        // Step 6: Respond with success
        return $response->withHeader('Content-Type', 'application/json')
            ->getBody()->write(json_encode([
                'status' => 'success',
                'message' => 'Book added successfully.',
                'book' => ['bookid' => $bookid, 'title' => $title, 'year' => $year, 'thumbnail' => $filename]
            ]));
    } catch (Exception $e) {
        return $response->withStatus(401)->withHeader('Content-Type', 'application/json')
            ->getBody()->write(json_encode(['status' => 'fail', 'message' => 'Invalid token.']));
    }
});


$app->get('/books', function (Request $request, Response $response, array $args) {
    // Step 1: Try to get JWT from cookies, but allow access even without a token
    $jwt = $_COOKIE['auth_token'] ?? null;

    // If the token is provided, attempt to decode it and validate
    if ($jwt) {
        try {
            // Step 2: Decode and validate the JWT token using the Key class
            $key = new Key('server_hack', 'HS256'); // Secret key
            $decoded = JWT::decode($jwt, $key);  // Decode the JWT token

            // Token decoded successfully (can be used for role-based logic, if needed)
        } catch (Exception $e) {
            // If decoding fails, return an unauthorized response
            return $response->withStatus(401)->write(json_encode(['status' => 'fail', 'message' => 'Invalid token.']));
        }
    }

    // Step 3: Fetch book details from the database
    $database = new Database();
    $conn = $database->getConnection();

    // SQL query to get book info with authors
    $sql = "
        SELECT b.bookid, b.title, b.year, b.thumbnail, GROUP_CONCAT(a.name) AS authors
        FROM books b
        LEFT JOIN book_authors ba ON b.bookid = ba.bookid
        LEFT JOIN authors a ON ba.authorid = a.authorid
        GROUP BY b.bookid
    ";

    $stmt = $conn->prepare($sql);
    $stmt->execute();

    // Step 4: Fetch all results
    $books = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Step 5: Prepare response data
    $responseData = [
        'status' => 'success',
        'books' => $books
    ];

    // Step 6: Set response content type to application/json and return the data
    return $response
        ->withHeader('Content-Type', 'application/json')
        ->write(json_encode($responseData));
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