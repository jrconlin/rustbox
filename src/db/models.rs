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
        let index = &self.idx;
        s.serialize_field("index", &(*index as u64))?;
        s.serialize_field("data", &String::from_utf8(data.to_vec()).unwrap())?;
        s.end()
    }
}

pub fn now_utc() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u64
}

pub fn calc_ttl(seconds: u64) -> u64 {
    now_utc() + seconds
}

/// An authorized broadcaster

pub struct DatabaseManager {}

impl DatabaseManager {
    pub fn max_index(conn: &MysqlConnection, user_id: &String, device_id: &String) -> u64 {
        let mut max_index_sel: Vec<i64> = match pushboxv1::table
            .select(pushboxv1::idx)
            .filter(pushboxv1::user_id.eq(user_id))
            .filter(pushboxv1::device_id.eq(device_id))
            .order(pushboxv1::idx.desc())
            .limit(1)
            .load::<i64>(conn)
        {
            Ok(val) => val,
            Err(_) => vec![],
        };
        max_index_sel.pop().unwrap_or(0) as u64
    }

    pub fn new_record(
        conn: &MysqlConnection,
        user_id: &String,
        device_id: &String,
        data: &String,
        ttl: u64,
    ) -> HandlerResult<u64> {
        let t_manager = conn.transaction_manager();
        t_manager
            .begin_transaction(conn)
            .context(HandlerErrorKind::DBError)?;
        insert_into(pushboxv1::table)
            .values((
                pushboxv1::user_id.eq(user_id),
                pushboxv1::device_id.eq(device_id),
                pushboxv1::ttl.eq(ttl as i64),
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
            .context(HandlerErrorKind::DBError)?;

        Ok(record_index as u64)
    }

    pub fn read_records(
        conn: &MysqlConnection,
        user_id: &String,
        device_id: &String,
        index: &Option<u64>,
        limit: &Option<u64>,
    ) -> HandlerResult<Vec<Record>> {
        // flatten into HashMap FromIterator<(K, V)>
        let mut query = pushboxv1::table
            .select((
                pushboxv1::user_id,   // NOTE: load() does not order these, so you should
                pushboxv1::device_id, // keep them in field order for Record{}
                pushboxv1::ttl,
                pushboxv1::idx,
                pushboxv1::data,
            ))
            .into_boxed();
        query = query
            .filter(pushboxv1::user_id.eq(user_id))
            .filter(pushboxv1::device_id.eq(device_id))
            .filter(pushboxv1::ttl.ge(now_utc() as i64));
        match index {
            None => {}
            Some(index) => {
                query = query.filter(pushboxv1::idx.ge(index.clone() as i64));
            }
        };
        match limit {
            None => {}
            Some(limit) => {
                query = query.limit(limit.clone() as i64);
            }
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
    ) -> HandlerResult<bool> {
        let mut query = diesel::delete(pushboxv1::table).into_boxed();
        query = query.filter(pushboxv1::user_id.eq(user_id));
        if !device_id.is_empty() {
            query = query.filter(pushboxv1::device_id.eq(device_id));
        }
        query.execute(conn)
            .context(HandlerErrorKind::DBError)?;
        Ok(true)
    }
}
