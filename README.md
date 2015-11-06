# VT Hunter
![alt tag](http://i.imgur.com/ohtxGJb.jpg)
![alt tag](http://i.imgur.com/5ZwF1w1.jpg)
![alt tag](http://i.imgur.com/lw2Rqgd.jpg)
![alt tag](http://i.imgur.com/qR1veRk.jpg)

A web interface to manage VT alerts locally (pulls them down from VT). Make it easier to search, filter, view, etc.  Also has ability to check files in Crits.  Written in PHP.

This will pull VT alets via the JSON api, store them into Mongo, and delete the alert on VT.

WHY?  I like to be able to quickly filter and search on ANY of the fields.  Sort.  Quickly see duplicates.  Integrate with Crits to validate if this is a new sample.  View the yara syntax it alerted on.  See if my AV detects it according to VT.  Quickly remove false positives, like file type C (someone uploading snort or yara rules) or giant files sizes, or only wanting Win32 Exe files, etc.

### Web Interface
  - Set the configs in config.php
  - Go to vt.php in browser

### Requirements
  - VT Intel API Key
  - VT Search API Key (optional for more data)
  - PHP
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
  - Make vt.log writtable

### FYI
  - Still working on Download Feature
  - If you want to see AV other than McAfee, change the name on line 295 of vt.php
  
  ```sh
  print "<td>".$array['scans']['McAfee']."</td>";
  ```
### Config Settings
  - Mongo Settings (database and collection)
  - Crits Settings (server and creds)
  - VT Settings
    - Hunting API Key (VirusTotal Intelligence)
    - Searching API key (VirusTotal Private Mass API)
    - Delete Alerts from VT

### UI Buttons
  - Samples = # of samples in DB
  - Download = no working right now
  - Delete = Delete record from DB
  - Pull VT = Grab alerts from VT
  - Log = Show Log
  - Config = Show some configs
  - Archive = Archive Results

### Coming Soon 
  - Graphs
  - Downloading
  - Notes
  - Redefine Crits integration

### TroubleShooting
  - PHP Short tags - http://stackoverflow.com/questions/2185320/how-to-enable-php-short-tags
  
    ```sh
    /etc/php5/apache2/php.ini:short_open_tag = On
    /etc/php5/cli/php.ini.ucf-old:short_open_tag = On
    /etc/php5/cli/php.ini:short_open_tag = On
    ```
