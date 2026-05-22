import json
import os
import sys
from elasticsearch import Elasticsearch

ES_HOST = "http://localhost:9200"
INDEX_NAME = "cogsoc-flows"
OUTPUT_HTML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lateral_graph.html")

def fetch_data():
    es = Elasticsearch(ES_HOST)
    if not es.indices.exists(index=INDEX_NAME):
        print(f"Index {INDEX_NAME} does not exist.")
        return []

    # Fetch last 10000 flows
    query = {
        "size": 10000,
        "query": {"match_all": {}},
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "boolean"}}]
    }

    try:
        res = es.search(index=INDEX_NAME, **query)
        return res["hits"]["hits"]
    except Exception as e:
        print(f"Error fetching from Elasticsearch: {e}")
        # Try fetching without sort if @timestamp fails
        try:
            query.pop("sort")
            res = es.search(index=INDEX_NAME, **query)
            return res["hits"]["hits"]
        except Exception as e2:
            print(f"Error fetching without sort: {e2}")
            return []

def is_internal(ip):
    if not ip:
        return False
    # Check for common private subnets
    return ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")

def generate_graph_data(hits):
    nodes_dict = {}
    edges_dict = {}

    for hit in hits:
        source = hit["_source"]
        src_ip = source.get("Src IP")
        dst_ip = source.get("Dst IP")
        if not src_ip or not dst_ip:
            continue

        # Strictly Lateral (East-West) Traffic: Only plot if both IPs are internal
        if not is_internal(src_ip) or not is_internal(dst_ip):
            continue

        # Add to nodes
        if src_ip not in nodes_dict:
            nodes_dict[src_ip] = {"id": src_ip, "name": src_ip, "value": 0, "category": 0}
        if dst_ip not in nodes_dict:
            nodes_dict[dst_ip] = {"id": dst_ip, "name": dst_ip, "value": 0, "category": 1}

        nodes_dict[src_ip]["value"] += 1
        nodes_dict[dst_ip]["value"] += 1

        # Add to edges
        edge_id = f"{src_ip}-{dst_ip}"
        if edge_id not in edges_dict:
            edges_dict[edge_id] = {"source": src_ip, "target": dst_ip, "value": 0}
        edges_dict[edge_id]["value"] += 1

    nodes = list(nodes_dict.values())
    
    # Scale node symbol sizes
    max_val = max([n["value"] for n in nodes]) if nodes else 1
    for n in nodes:
        # Scale between 10 and 50
        n["symbolSize"] = 10 + (n["value"] / max_val) * 40

    edges = list(edges_dict.values())
    return nodes, edges

def create_html(nodes, edges):
    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CogSOC Lateral Network Graph</title>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.5.0/dist/echarts.min.js"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&display=swap');
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            background: radial-gradient(circle at center, #1a1e29 0%, #0f111a 100%);
            color: #fff;
            font-family: 'Inter', sans-serif;
            overflow: hidden;
            height: 100vh;
            width: 100vw;
        }}
        
        #graph-container {{
            width: 100%;
            height: 100%;
            position: absolute;
            top: 0;
            left: 0;
            z-index: 1;
        }}
        
        .sidebar {{
            position: absolute;
            top: 20px;
            right: 20px;
            width: 320px;
            background: rgba(20, 24, 34, 0.6);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            padding: 24px;
            z-index: 10;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            transition: transform 0.3s ease;
        }}
        
        .header {{
            margin-bottom: 24px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding-bottom: 16px;
        }}
        
        h1 {{
            font-size: 1.25rem;
            font-weight: 600;
            letter-spacing: -0.025em;
            background: linear-gradient(135deg, #00f2fe 0%, #4facfe 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 4px;
        }}
        
        p.subtitle {{
            font-size: 0.8rem;
            color: #94a3b8;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 24px;
        }}
        
        .stat-card {{
            background: rgba(255, 255, 255, 0.03);
            border-radius: 12px;
            padding: 16px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }}
        
        .stat-value {{
            font-size: 1.5rem;
            font-weight: 600;
            color: #fff;
            margin-bottom: 4px;
        }}
        
        .stat-label {{
            font-size: 0.75rem;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        
        .info-panel {{
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.2);
            border-radius: 8px;
            padding: 12px;
            font-size: 0.85rem;
            color: #a7f3d0;
            line-height: 1.5;
        }}
        
        .legend {{
            margin-top: 24px;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            margin-bottom: 8px;
            font-size: 0.85rem;
            color: #cbd5e1;
        }}
        
        .legend-color {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 12px;
        }}
        
        .color-src {{ background: #ff4b4b; box-shadow: 0 0 10px #ff4b4b; }}
        .color-dst {{ background: #00f2fe; box-shadow: 0 0 10px #00f2fe; }}
        
        /* Floating particles effect in background */
        .particles {{
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            pointer-events: none;
            z-index: 0;
            background-image: radial-gradient(rgba(255,255,255,0.05) 1px, transparent 1px);
            background-size: 50px 50px;
        }}
    </style>
</head>
<body>
    <div class="particles"></div>
    <div id="graph-container"></div>
    
    <div class="sidebar">
        <div class="header">
            <h1>Lateral Attack Graph</h1>
            <p class="subtitle">Network Flow Correlation</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{len(nodes)}</div>
                <div class="stat-label">Active Nodes</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{len(edges)}</div>
                <div class="stat-label">Connections</div>
            </div>
        </div>
        
        <div class="info-panel">
            Visualizing dynamic network topology and lateral movement vectors based on recent flow data.
        </div>
        
        <div class="legend">
            <div class="legend-item">
                <div class="legend-color color-src"></div>
                <span>Source Nodes (Attackers/Clients)</span>
            </div>
            <div class="legend-item">
                <div class="legend-color color-dst"></div>
                <span>Target Nodes (Victims/Servers)</span>
            </div>
        </div>
    </div>

    <script>
        var nodesData = {json.dumps(nodes)};
        var edgesData = {json.dumps(edges)};
        
        var chartDom = document.getElementById('graph-container');
        var myChart = echarts.init(chartDom, 'dark');
        var option;

        myChart.showLoading({{
            text: 'Analyzing Topology...',
            color: '#00f2fe',
            textColor: '#fff',
            maskColor: 'rgba(15, 17, 26, 0.8)'
        }});

        setTimeout(function() {{
            myChart.hideLoading();
            
            option = {{
                backgroundColor: 'transparent',
                tooltip: {{
                    trigger: 'item',
                    backgroundColor: 'rgba(20, 24, 34, 0.9)',
                    borderColor: 'rgba(255,255,255,0.1)',
                    textStyle: {{ color: '#fff' }},
                    formatter: function (params) {{
                        if (params.dataType === 'node') {{
                            return `<div style="font-weight:bold;margin-bottom:4px;border-bottom:1px solid rgba(255,255,255,0.2);padding-bottom:4px;">IP: ${{params.data.name}}</div>
                                    Flows: ${{params.data.value}}`;
                        }} else {{
                            return `${{params.data.source}} <br/> ⟷ <br/> ${{params.data.target}}<br/>Flows: ${{params.data.value}}`;
                        }}
                    }}
                }},
                series: [
                    {{
                        type: 'graph',
                        layout: 'force',
                        nodes: nodesData,
                        edges: edgesData,
                        roam: true,
                        draggable: true,
                        label: {{
                            show: true,
                            position: 'right',
                            formatter: '{{b}}',
                            color: '#e2e8f0',
                            fontSize: 11
                        }},
                        categories: [
                            {{ name: 'Source', itemStyle: {{ color: '#ff4b4b', shadowBlur: 20, shadowColor: '#ff4b4b' }} }},
                            {{ name: 'Destination', itemStyle: {{ color: '#00f2fe', shadowBlur: 20, shadowColor: '#00f2fe' }} }}
                        ],
                        force: {{
                            repulsion: 400,
                            edgeLength: 120,
                            gravity: 0.1
                        }},
                        lineStyle: {{
                            color: 'source',
                            curveness: 0.2,
                            opacity: 0.4,
                            width: 1.5
                        }},
                        emphasis: {{
                            focus: 'adjacency',
                            lineStyle: {{
                                width: 3,
                                opacity: 1
                            }}
                        }}
                    }}
                ]
            }};

            myChart.setOption(option);
            
            // Handle window resize
            window.addEventListener('resize', function() {{
                myChart.resize();
            }});
        }}, 800);
    </script>
</body>
</html>
"""
    with open(OUTPUT_HTML, "w", encoding="utf-8") as f:
        f.write(html_template)
    print(f"Generated stunning visualization at: {OUTPUT_HTML}")

if __name__ == "__main__":
    print("Fetching network flow data from Elasticsearch...")
    hits = fetch_data()
    if not hits:
        print("No data found or Elasticsearch is unreachable. Using simulated data for demonstration.")
        # Fallback simulated data if ES is empty
        hits = [
            {"_source": {"Src IP": "192.168.100.45", "Dst IP": "10.0.0.5"}},
            {"_source": {"Src IP": "192.168.100.45", "Dst IP": "10.0.0.6"}},
            {"_source": {"Src IP": "192.168.100.45", "Dst IP": "10.0.0.7"}},
            {"_source": {"Src IP": "192.168.100.12", "Dst IP": "10.0.0.5"}},
            {"_source": {"Src IP": "10.0.0.5", "Dst IP": "8.8.8.8"}},
            {"_source": {"Src IP": "10.0.0.6", "Dst IP": "8.8.4.4"}},
        ] * 10 # multiply to add weights
        
    print(f"Found {len(hits)} flows. Generating graph...")
    nodes, edges = generate_graph_data(hits)
    create_html(nodes, edges)
    print("Done. Open the HTML file in a browser to view the Lateral Attack Graph.")
