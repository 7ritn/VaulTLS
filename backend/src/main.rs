#[macro_use]
extern crate rocket;

use vaultls::create_rocket;

#[launch]
async fn rocket() -> _ {
    create_rocket().await
}
