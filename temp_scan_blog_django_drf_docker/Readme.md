# My Blog Project

This project is a simple blog application built with Django and Python. It allows users to create, edit, and delete blog posts.

## Development Setup

1. Clone the repository to your local machine.
2. Install the required dependencies by running `pip install -r requirements.txt` in your terminal.
3. Run the Django server with `python manage.py runserver`.
4. The application will be available at [http://localhost:8000](http://localhost:8000).

## Testing

This project uses Django's built-in testing framework. To run the tests, use the command `python manage.py test`.

## Production Deployment

This project includes a Dockerfile for containerization, which makes it ready for production deployment. Here are the steps to deploy it using Docker:

1. Build the Docker image with `docker build -t myblog .`.
2. Run the Docker container with `docker run -d -p 8000:8000 myblog`.
3. The application will be available at [http://localhost:8000](http://localhost:8000).

## Project Structure

The project is structured as follows:

- **blog/:** This directory contains the Django application for the blog. It includes the templates for the blog posts and the home page.
- **myblog/:** This directory contains the settings for the Django project.
- **manage.py:** This is the command-line utility for administrative tasks in Django.
- **Dockerfile:** This file is used to create a Docker image of the application.
- **.dockerignore and .gitignore:** These files specify the files and directories that Docker and Git should ignore.

## Contributing

Contributions are welcome. Please fork the repository and create a pull request with your changes.

## License

This project is licensed under the terms of the MIT license.