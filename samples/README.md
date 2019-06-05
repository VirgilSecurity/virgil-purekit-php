## PureKit PHP Sample

This code provides a sample usage of PureKit in PHP.

To make things simple, it uses a json files (user_table.json and main_table.json) as a database.

### Steps to run encrypt (main) flow:
- Create a Pure App in your Virgil Security Dashboard
- Clone repository
- Install dependencies with `composer install`
- Restore defaults: `php _defaults.php --with-env`
- Replace your credentials in **.env** file
- Run main.php: `php main.php`
- user_table.json should contains records
- main_table.json should contains recovery_public_key

### Steps to rotate records:
- Start rotation process in Dashboard
- Add your UPDATE_TOKEN in **.env** file
- Run rotate.php: `php rotate.php`
- user_table.json should contain new records
- Finish rotation process in Dashboard
- Update your credentials in **.env** file

### Steps to recover standard passwords:
- Run **rotate.php**: `php recovery.php`

### Steps to restore defaults:
- Restore defaults with **env** file: `php _defaults.php --with-env`
- Restore defaults without **env** file: `php _defaults.php`