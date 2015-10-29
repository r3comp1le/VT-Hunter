# VT Hunter
![alt tag](http://i.imgur.com/mEH2mvW.jpg)
![alt tag](http://i.imgur.com/pImqBs8.jpg)
![alt tag](http://i.imgur.com/juS8ebW.jpg)

A web interface to manage VT alerts locally. Make it easier to search, filter, view, etc.  Also has ability to check files in Crits.  Written in PHP.

This will pull VT alets via the JSON api, store them into Mongo, and delete the alert on VT.

WHY?  I like to be able to quickly filter and search on ANY of the fields.  Sort.  Quickly see duplicates.  Integrate with Crits to validate if this is a new sample.  View the yara syntax it alerted on.  See if my AV detects it according to VT.  Quickly remove false positives, like file type C (someone uploading snort or yara rules) or giant files sizes, or only wanting Win32 Exe files, etc.

### Web Interface
  - Set the configs in config.php
  - Go to vt.php in browser

### Requirements
  - VT Intel API Key
  - PHP
  - mongodb and mongo php
  ```sh
  apt-get install php-pear
  ```
  
  - http://pecl.php.net/pack/mongo (Download tgz)
    
  ```sh
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

### Coming Soon 
  - Integrate VT search API to acquire more details on samples
