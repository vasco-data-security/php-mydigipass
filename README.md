# Php-mydigipass

A very simple php program showing how easy it is to integrate with MYDIGIPASS.COM and add MYDIGIPASS.COM Secure two factor authentication to your php site.

All enhancement proposals can be submitted to our github and will be considered to become part of the official code base.

The MYDIGIPASS.COM Development team.

## To get it working

First off you need to clone this project in some folder where your webbrowser will pick it up.

In ubuntu this normally is located in the folder `/var/www`.

You also need to make sure that `curl` is installed on your system, and your php is configured to use 
it (uncomment the line in your `php.ini`).

Then take the following steps:

* go to the [developer](https://developer.mydigipass.com) site
* create a test site, with `redirect_uri` equal to `http://localhost/php-mydigipass/index.php` 
* you get a `client_id` and a `client_secret`
* copy the `mydigipass-config-example.php` file to `mydigipass-config.php` and fill in your `client-id` and `client-secret`
* open the browser, browse to `http://localhost/php-mydigipass/index.php` and see magic :)

Hope this helps.

## License

Copyright (c) 2012 VASCO Data Security Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
