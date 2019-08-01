INSERT INTO customer
(email, hash_value)
VALUES
(${email}, ${hash_value})
RETURNING *;