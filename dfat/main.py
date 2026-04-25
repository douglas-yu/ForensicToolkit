"""
DFAT - Digital Forensics Analysis Tool
Main application entry point
"""

import sys
from pathlib import Path
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dfat.gui.main_window import MainWindow
from dfat.config import Config
from dfat.utils.logger import setup_logger

logger = setup_logger(__name__)


def main():
    """Application entry point"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Initialize configuration
    config = Config()
    logger.info("=" * 80)
    logger.info("Starting DFAT - Digital Forensics Analysis Tool")
    logger.info(f"Configuration loaded from: {config.config_file}")
    logger.info(f"Server URL: {config.server_url}")
    logger.info(f"Evidence Directory: {config.evidence_dir}")
    logger.info("=" * 80)
    
    # Create and show main window
    window = MainWindow(config)
    window.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
