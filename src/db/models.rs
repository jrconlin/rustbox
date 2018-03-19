use std::time::{SystemTime, UNIX_EPOCH};

use diesel::connection::TransactionManager;
use diesel::mysql::MysqlConnection;
use diesel::{self, insert_into, Connection, ExpressionMethods, QueryDsl, RunQueryDsl};
use failure::ResultExt;
use serde::ser::{Serialize, SerializeStruct, Serializer};

use super::schema::pushboxv1;
use error::{HandlerErrorKind, HandlerResult};

#[derive(Debug, Queryable, Insertable)]
#[table_name = "pushboxv1"]
pub struct Record {
    pub user_id: String,
    pub device_id: String,
    pub service: String,
    pub ttl: i64, // expiration date in UTC.
    pub idx: i64,
    pub data: Vec<u8>,
}

impl Serialize for Record {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data = &self.data.clone();
        let mut s = serializer.serialize_struct("Record", 2)?;
        s.serialize_field("index", &self.idx)?;
        s.serialize_field("data", &String::from_utf8(data.to_vec()).unwrap())?;
        s.end()
    }
}

pub fn now_utc() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub fn calc_ttl(seconds: i64) -> i64 {
    now_utc() + seconds
}

/// An authorized broadcaster

pub struct DatabaseManager {}

impl DatabaseManager {
    pub fn max_index(
        conn: &MysqlConnection,
        user_id: &String,
        device_id: &String,
        service: &String,
    ) -> i64 {
        let mut max_index_sel: Vec<i64> = match pushboxv1::table
            .select(pushboxv1::idx)
            .filter(pushboxv1::user_id.eq(user_id))
            .filter(pushboxv1::device_id.eq(device_id))
            .filter(pushboxv1::service.eq(service))
            .order(pushboxv1::idx.desc())
            .limit(1)
            .load::<i64>(conn)
        {
            Ok(val) => val,
            Err(_) => vec![],
        };
        max_index_sel.pop().unwrap_or(0)
    }

    pub fn new_record(
        conn: &MysqlConnection,
        user_id: &String,
        device_id: &String,
        service: &String,
        data: &String,
        ttl: i64,
    ) -> HandlerResult<i64> {
        let t_manager = conn.transaction_manager();
        t_manager
            .begin_transaction(conn)
            .expect("Could not create transaction");
        insert_into(pushboxv1::table)
            .values((
                pushboxv1::user_id.eq(user_id.to_string()),
                pushboxv1::device_id.eq(device_id.to_string()),
                pushboxv1::service.eq(service.to_string()),
                pushboxv1::ttl.eq(ttl),
                pushboxv1::data.eq(data.clone().into_bytes()),
            ))
            .execute(conn)
            .context(HandlerErrorKind::DBError)?;
        let record_index = match pushboxv1::table
            .select(pushboxv1::idx)
            .order(pushboxv1::idx.desc())
            .limit(1)
            .load::<i64>(conn)
        {
            Ok(val) => val[0],
            Err(_) => return Err(HandlerErrorKind::DBError.into()),
        };
        t_manager
            .commit_transaction(conn)
            .expect("Could not close transaction");

        Ok(record_index)
    }

    pub fn read_records(
        conn: &MysqlConnection,
        user_id: &String,
        device_id: &String,
        service: &String,
        index: i64,
        limit: i64,
    ) -> HandlerResult<Vec<Record>> {
        // flatten into HashMap FromIterator<(K, V)>
        let mut query = pushboxv1::table
            .select((
                pushboxv1::user_id,   // NOTE: load() does not order these, so you should
                pushboxv1::device_id, // keep them in field order for Record{}
                pushboxv1::service,
                pushboxv1::ttl,
                pushboxv1::idx,
                pushboxv1::data,
            ))
            .into_boxed();
        query = query
            .filter(pushboxv1::user_id.eq(user_id.clone()))
            .filter(pushboxv1::device_id.eq(device_id.clone()))
            .filter(pushboxv1::service.eq(service.clone()))
            .filter(pushboxv1::ttl.ge(now_utc()));
        if index > 0 {
            query = query.filter(pushboxv1::idx.ge(index));
        }
        if limit > 0 {
            query = query.limit(limit);
        }
        Ok(query
            .order(pushboxv1::idx)
            .load::<Record>(conn)
            .context(HandlerErrorKind::DBError)?
            .into_iter()
            .collect())
    }

    pub fn delete(
        conn: &MysqlConnection,
        user_id: &String,
        device_id: &String,
        service: &String,
    ) -> HandlerResult<bool> {
        // boxed deletes are "coming soon"
        // see https://github.com/diesel-rs/diesel/pull/1534
        if device_id.len() > 0 {
            diesel::delete(
                pushboxv1::table
                    .filter(pushboxv1::user_id.eq(user_id.clone()))
                    .filter(pushboxv1::service.eq(service.clone()))
                    .filter(pushboxv1::device_id.eq(device_id.clone())),
            ).execute(conn)
                .context(HandlerErrorKind::DBError)?;
        } else {
            diesel::delete(
                pushboxv1::table
                    .filter(pushboxv1::user_id.eq(user_id.clone()))
                    .filter(pushboxv1::service.eq(service.clone())),
            ).execute(conn)
                .context(HandlerErrorKind::DBError)?;
        }
        Ok(true)
    }
}
