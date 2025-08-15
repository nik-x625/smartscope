"""
Entry point for SmartScope Backend application
"""

import os
from app import create_app

# Create Flask app instance
app = create_app(os.environ.get('FLASK_ENV', 'development'))

if __name__ == '__main__':
    # Get configuration
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 9000))
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Run the application
    app.run(
        host=host,
        port=port,
        debug=debug
    )
