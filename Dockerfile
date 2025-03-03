FROM node:18

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm config set registry https://registry.npmjs.org/ && \
    npm config set fetch-timeout 60000 && \
    npm cache clean --force && \
    npm install --only=production


# Copy all project files
COPY . .

# Automatically make all .sh files executable
RUN find . -type f -name "*.sh" -exec chmod +x {} \;

# Install AWS CLI (example for Debian/Ubuntu-based images)
RUN apt-get update && apt-get install -y unzip curl && \
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install && \
    rm -rf aws awscliv2.zip && \
    rm -rf /var/lib/apt/lists/*


EXPOSE 3001

ENTRYPOINT ["./build.sh"]


