FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy application files
COPY . .

# Build application
RUN npm run build

# Install serve to run the application
RUN npm install -g serve

# Expose port (as defined in docker-compose.yml)
EXPOSE 3000

# Start the application
CMD ["serve", "-s", "dist", "-l", "3000"]
