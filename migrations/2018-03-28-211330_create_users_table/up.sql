CREATE TABLE pushboxv1 (
    user_id Varchar(200) Not Null,
    device_id Varchar(200),
    service Varchar(16) Not Null,
    data Blob,
    idx BigInt Auto_Increment,
    ttl BigInt,
    Primary Key(idx)
);
Create Index user_id_idx on pushboxv1 (user_id);
Create Index full_idx on pushboxv1 (user_id, device_id, service);
