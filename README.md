# VT Hunter
![alt tag](http://i.imgur.com/mEH2mvW.jpg)
![alt tag](http://i.imgur.com/pImqBs8.jpg)
![alt tag](http://i.imgur.com/juS8ebW.jpg)

A tool to manage VT alerts locally. Make it easier to search, filter, view, etc.  Also has ability to check files in Crits.  Written in PHP

### Web Interface
  - Set the configs in config.php

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

### FYI
  - Still working on Download Feature

### Coming Soon 
  - Integrate VT search API to acquire more details on samples
