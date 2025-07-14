# Spring Boot 3.0 JWT Authentication & Authorization

## Dockerized Deployment

### Prerequisites
- Docker & Docker Compose installed

### Build and Run

1. **Build and start the app with MySQL:**
   ```sh
   docker-compose up --build
   ```
   This will build the Spring Boot app and start both the app and a MySQL 8.0 database.

2. **Access the app:**
   - App: http://localhost:8080
   - MySQL: localhost:3306 (user: root, password: root, db: proddb)

3. **Stop the containers:**
   ```sh
   docker-compose down
   ```

### Environment Variables
- The app is configured to use the `prod` profile and connect to the MySQL container by default.
- You can override DB credentials or other Spring Boot properties in `docker-compose.yml` as needed.

### Notes
- The MySQL data is persisted in a Docker volume (`db_data`).
- For production, change the default passwords and consider using secrets management. 