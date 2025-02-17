FROM node:16

# Set working directory inside the container
WORKDIR /usr/src/app

# Copy package files and install dependencies (this compiles native modules for Linux)
COPY package*.json ./
RUN npm install --only=production

# Copy the rest of your application code
COPY . .

# Expose the app port
EXPOSE 3001

# Start the application
CMD ["npm", "start"]
