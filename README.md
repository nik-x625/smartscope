# SmartScope - Document Management System

A modern sales process management system designed to streamline every stage of the RFI and RFP lifecycle. From scope development and effort estimation to time-plan generation and beyond, this platform offers a comprehensive suite of features to simplify complex sales workflows. Leveraging advanced AI capabilities, the system automates critical tasks throughout the tender process, saving your team countless hours each day and enabling them to focus on what matters most-winning more business.

<img width="1662" alt="image" src="https://github.com/user-attachments/assets/81746b04-4757-4462-8880-8514e35e60bf" />

# AI-Powered Document Assistant
AI assistant helps to create or adjust the templates or documents with simple prompts

<img width="637" alt="image" src="https://github.com/user-attachments/assets/18850882-a2e3-4889-b485-3f8fd3c61ff4" />


## Keywords
`smart scope development`, `sales process automation`, `tender process`, `smart tender`, `easy tender`,`effort estimation`, `time plan`, `project proposal`, `budgetary indication`, `rfp`, `rfi`, `rfx`, `cloud native`, `saas`, `high-availability`, `AI`, `RAG`, `machine learning`, `smart database training`, `SmartScope`, `Document Management System`, `DMS`, `Real-time Editing`, `Document Templating`, `Document Versioning`, `Hierarchical Documents`, `Content Management`, `Auto-saving`, `Python`, `Flask`, `HTMX`, `Bootstrap 5`, `MongoDB`, `JavaScript`, `Jinja2`, `User Authentication`, `Rich Text Editor`, `Responsive Design`, `Dark Mode`, `Web Application`, `Full-Stack Development`, `Productivity Tool`

## Features

- **User Authentication**
  - Secure login and registration system
  - User session management
  - Account deletion with data cleanup

- **Document Management**
  - Create and edit documents with a rich text editor
  - Hierarchical document structure (chapters, sections)
  - Real-time auto-saving
  - Document templates
  - Document versioning

- **Modern UI/UX**
  - Responsive design using Bootstrap 5
  - Dark mode support
  - HTMX for dynamic content updates
  - Bootstrap Icons for visual elements
  - Real-time updates without page refreshes

- **Security**
  - Password hashing
  - Session management
  - Protected routes
  - Secure MongoDB integration

## Tech Stack

- **Backend**
  - Flask 3.1.0
  - MongoDB (PyMongo 4.12.0)
  - Flask-Login 0.6.3
  - Gunicorn 23.0.0

- **Frontend**
  - Bootstrap 5.3.2
  - HTMX (enables dynamic, interactive web apps without complex JavaScript)
  - Bootstrap Icons 1.11.1



## Prerequisites

- Python 3.x
- Docker and Docker Compose
- MongoDB (included in Docker setup)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd docker_smartscope_htmx_bootstrap
```

2. Start the application using Docker Compose:
```bash
docker-compose up --build
```

The application will be available at `http://localhost:8000`

## Development Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Run the development server:
```bash
flask run
```

## Project Structure

```
.
├── app.py                 # Main application file
├── config.py             # Configuration settings
├── database.py           # Database connection and services
├── requirements.txt      # Python dependencies
├── Dockerfile           # Docker configuration
├── docker-compose.yml   # Docker services configuration
├── static/              # Static files (CSS, JS)
├── templates/           # HTML templates
│   ├── partials/       # Reusable template components
│   └── ...
├── models_for_documents/  # Document-related models
├── models_for_flask_login/ # Authentication models
└── logs/                # Application logs
```

## Features in Detail

### Document Management
- Create documents with a hierarchical structure
- Real-time auto-saving
- Document templates for quick creation
- Rich text editing capabilities
- Document versioning and history

### User Interface
- Responsive design that works on all devices
- Dark mode support
- Dynamic content updates using HTMX
- Bootstrap 5 components and utilities
- Modern icon set with Bootstrap Icons

### Security Features
- Secure password hashing
- Session-based authentication
- Protected routes and resources
- MongoDB security best practices

## Contributing

We welcome contributions! Here's how you can help:

1.  **Fork the repository.**
2.  **Create a feature branch** for your new feature or bug fix. (e.g., `git checkout -b feature/awesome-new-feature` or `git checkout -b fix/annoying-bug`)
3.  **Make your changes** and commit them with clear, descriptive messages.
4.  **Add tests** for any new features or bug fixes.
5.  **Ensure your code follows existing style guidelines.**
6.  **Update documentation** if your changes require it.
7.  **Push your branch** to your fork. (e.g., `git push origin feature/awesome-new-feature`)
8.  **Open a Pull Request** against the `main` (or `develop`) branch of the original repository.
    *   Clearly describe the changes you've made and why.
    *   Link to any relevant issues.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

