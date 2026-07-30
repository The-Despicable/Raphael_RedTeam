from typing import Optional


BLOODHOUND_QUERIES = {
    "find_da": """
        MATCH (n:User) WHERE n.domainadmin = true RETURN n.name, n.domain
    """,
    "shortest_path_da": """
        MATCH (n:User), (m:Group {name: 'DOMAIN ADMINS@TEST.LOCAL'}),
        p = shortestPath((n)-[:MemberOf*1..]->(m))
        RETURN n.name, length(p) as hops
        LIMIT 20
    """,
    "all_users": """
        MATCH (n:User) RETURN n.name, n.displayname, n.domain LIMIT 100
    """,
    "all_computers": """
        MATCH (n:Computer) RETURN n.name, n.operatingsystem LIMIT 100
    """,
    "admin_sessions": """
        MATCH (n:Computer)<-[r:AdminTo]-(u:User) RETURN u.name, n.name LIMIT 50
    """,
    "constrained_delegation": """
        MATCH (n:Computer) WHERE n.constraineddelegation = true
        RETURN n.name, n.msallowed-delegateto LIMIT 20
    """,
    "kerberoastable": """
        MATCH (n:User) WHERE n.hasspn = true
        RETURN n.name, n.serviceprincipalnames LIMIT 50
    """,
}


class BloodHoundIntegration:
    def __init__(self, uri: str = "bolt://neo4j:7687",
                 user: str = "neo4j", password: str = "raphael-dev"):
        self._uri = uri
        self._user = user
        self._password = password
        self._driver = None

    @property
    def available(self) -> bool:
        try:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(self._uri, auth=(self._user, self._password))
            self._driver.verify_connectivity()
            return True
        except Exception:
            return False

    def run_query(self, query_name: str = None, custom_query: str = None) -> dict:
        if custom_query:
            query = custom_query
        elif query_name and query_name in BLOODHOUND_QUERIES:
            query = BLOODHOUND_QUERIES[query_name]
        else:
            return {"error": f"Unknown query: {query_name}. Available: {list(BLOODHOUND_QUERIES.keys())}"}

        try:
            from neo4j import GraphDatabase
            if not self._driver:
                self._driver = GraphDatabase.driver(self._uri, auth=(self._user, self._password))
            records = []
            with self._driver.session() as session:
                result = session.run(query)
                for record in result:
                    records.append(dict(record))
            return {
                "query": query_name or "custom",
                "results": records,
                "count": len(records),
            }
        except ImportError:
            return {"error": "neo4j driver not installed. pip install neo4j"}
        except Exception as e:
            return {"error": str(e), "note": "Is BloodHound/Neo4j running?"}

    def find_da(self) -> dict:
        return self.run_query("find_da")
