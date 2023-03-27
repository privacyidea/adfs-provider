## 2023-03-27 v1.2.0

### Features
* Token enrollment via challenge-response
* Preferred client mode can be set from the server


## 2022-10-20 v1.1.1

### Enhancement
* Add German (de-de) and British English (en-gb) as supported languages.


## 2022-08-25 v1.1.0

### Features
* Option to enroll TOTP token if the user has none. This requires a service account to be set (#17)
* Option to forward selected headers (#24)
* Option to set the TLS version explicitly. By default the system version is used as advised by Microsoft (#23)
* Option to set a custom hint for the OTP input (#21)
* Option to set the preferred token type (if such token was triggered, see docs) (#32)

### Fixes
* If a user has multiple WebAuth token, all of them will be usable now (#29)


## 2021-07-20 v1.0.0

### Fixes
* Fixed an issue that would prevent multiple consecutive challenges from working


## 2021-07-06 v0.10.0

### Features
* WebAuthn
* Configurable Windows Domain to privacyIDEA realm mapping


## 2021-06-10 v0.9.0

### Features
* OTP Token like HOTP and TOTP
* Challenge-Response with Email and SMS
* Push Token
* MSI Installer
