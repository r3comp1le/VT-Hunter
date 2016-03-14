# VT Hunter
![alt tag](http://i.imgur.com/3j0azyY.jpg)
[![Video](https://blog.majestic.com/wp-content/uploads/2010/10/Video-Icon-crop.png)](https://streamable.com/v83x)

### OnGoing Project

A web interface to manage VT alerts locally (pulls them down from VT). Make it easier to search, filter, view, etc.  Also has ability to check files in Crits and soon to be MISP.  Written in PHP.

This will pull VT alerts via the JSON api, store them into Mongo, and delete the alert on VT.

WHY?  I like to be able to quickly filter and search on ANY of the fields.  Sort results.  Quickly see duplicates.  Integrate with Crits to validate if this is a new sample.  View the yara syntax it alerted on.  See if my AV detects it according to VT.  Quickly remove false positives, like file type C (someone uploading snort or yara rules) or giant files sizes, or only wanting Win32 Exe files, etc.

### Web Interface
  - All configuration is done in config.php
  - Navigate to vt.php in browser to use

### Requirements
  - VirusTotal Intelligence API
  - VirusTotal Private Mass API (optional for more data)
  - Apache (apt-get install apache2)
  - PHP (apt-get install php5 libapache2-mod-php5 php5-mcrypt)
  - mongodb and mongo php
  ```sh
  apt-get install php-pear
  ```
  
  - http://pecl.php.net/pack/mongo (Download tgz)
    
  ```sh
  sudo apt-get install php5-dev
  phpize
  ./configure
  make
  sudo make install
  sudo nano /etc/php5/apache2/php.ini
  extension=mongo.so (add to file)
  ```
  - Make vt.log writtable with appropriate permissions

### Install for Ubuntu 14.04
  - Copy all files to /var/www/html/vt (/vt will be your VT Hunter directory of choice)
  - Set appropriate permissions on files and directories
  
### Config Settings
  - Mongo Settings (Set: Host, Port, Database and Collection)
  - Crits Settings (Set: URL and API Key&User)
  - VT Settings
    - Hunting API Key (VirusTotal Intelligence)
    - Searching API key (VirusTotal Private Mass API)
    - Delete Alerts from VT

### UI Buttons
  - Samples = # of samples in database
  - Download = Downloaded and put into "infected" ZIP file
  - Delete = Delete record from database
  - Pull VT = Grab alerts from VT json feed
  - Pull Crits = Check if sample exists in Crits
  - Log = Show Log
  - Config = Show configs
  - Archive = Archive a record

### TroubleShooting
  - If you see php code when loading, probably means PHP Short tags isnt enabled
  - PHP Short tags - http://stackoverflow.com/questions/2185320/how-to-enable-php-short-tags
  
    ```sh
    /etc/php5/apache2/php.ini:short_open_tag = On
    /etc/php5/cli/php.ini.ucf-old:short_open_tag = On
    /etc/php5/cli/php.ini:short_open_tag = On
    ```
	
  - Make sure you Crits URL is correct. The $crits_url should be everything BEFORE the /api/v1
