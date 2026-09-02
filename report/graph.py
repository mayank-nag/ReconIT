import networkx as nx
from pyvis.network import Network
import os

def generate(target_data: dict, output_path: str) -> bool:
    try:
        G = nx.Graph()
        
        target = target_data.get('target', 'unknown_target')
        # Root node
        G.add_node(target, size=30, color='#388bfd', title='Root Domain', label=target)
        
        # Subdomains
        subdomains = target_data.get('subdomains', [])
        for sub in subdomains:
            # Check risks in subdomains later if needed
            G.add_node(sub, size=20, color='#2ea043', title='Subdomain', label=sub)
            G.add_edge(target, sub)
            
        # Crawled pages
        pages = target_data.get('pages_crawled', [])
        for page in pages:
            url = page.get('url', '')
            if url:
                status = page.get('status', 200)
                if status >= 500:
                    node_color = '#f85149' # Red
                elif status >= 400:
                    node_color = '#d29922' # Yellow
                else:
                    node_color = '#2ea043' # Green
                    
                G.add_node(url, size=10, color=node_color, title=f"Page (Status: {status})", label=url.split('/')[-1] or url)
                
                # Link page to its subdomain if matches, else to root
                parent_sub = None
                for sub in subdomains:
                    if sub in url:
                        parent_sub = sub
                        break
                
                if parent_sub:
                    G.add_edge(parent_sub, url)
                else:
                    G.add_edge(target, url)

        net = Network(height='750px', width='100%', bgcolor='#0d1117', font_color='white')
        net.from_nx(G)
        
        # Optional: enable physics for a nice interactive feel
        net.toggle_physics(True)
        
        net.save_graph(output_path)
        return True
    except Exception as e:
        print(f"Error generating graph: {e}")
        return False
