## PureKit PHP Sample

This code provides a sample usage of PureKit in PHP. 

To make things simple, it uses a json file user_table.json as a database.

### Steps to run:

- Create a Pure App in your Virgil Security Dashboard
- Replace your credentials in `main.php`
- Install dependencies with `composer install`
- Run main.php: `php main.php`
- user_table.json should contain records now.


### Steps to rotate records:

- Start rotation process in Dashboard
- Replace your credentials in `rotate.php`
- Run rotate.php: `php rotate.php`
- user_table.json should contain new records
- Finish rotation process in Dashboard
- Update your credentials in `main.php`