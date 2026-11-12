"""
Interactive 5-Stage Rupee-to-USDT Sankey Laundering Canvas (Sub-Engine 9.3A).
Computes 5-column stage stratification, clamped hybrid power-law ribbon scaling (gamma = 0.40),
Split-UPI Smurfing Fans, P2P Triangulation Mismatch badges, and top-arched circular feedback arcs.
"""

from src.financial_graph_and_storyboard.models import (
    SankeyFlowRibbon,
    SankeyLayoutResult,
    SankeyNode,
    SankeyStageColumn,
    SmurfingFanGroup,
)


class SankeyLaunderingCanvas:
    """Computes coordinates, Bézier flow paths, and smurfing fans for the laundering canvas."""

    STAGE_X_COORDINATES = {
        SankeyStageColumn.STAGE_1_EXTERNAL_INFLOW_SOURCES: 100.0,
        SankeyStageColumn.STAGE_2_LOCAL_MULE_ACCOUNTS_AND_VPAS: 350.0,
        SankeyStageColumn.STAGE_3_P2P_ESCROW_AND_DOMESTIC_FIU_ONRAMPS: 600.0,
        SankeyStageColumn.STAGE_4_SELF_CUSTODY_AND_CEX_WALLETS: 850.0,
        SankeyStageColumn.STAGE_5_OFFSHORE_BOSS_AND_PRIVACY_SWAPS: 1100.0,
    }

    STAGE_ORDER = [
        SankeyStageColumn.STAGE_1_EXTERNAL_INFLOW_SOURCES,
        SankeyStageColumn.STAGE_2_LOCAL_MULE_ACCOUNTS_AND_VPAS,
        SankeyStageColumn.STAGE_3_P2P_ESCROW_AND_DOMESTIC_FIU_ONRAMPS,
        SankeyStageColumn.STAGE_4_SELF_CUSTODY_AND_CEX_WALLETS,
        SankeyStageColumn.STAGE_5_OFFSHORE_BOSS_AND_PRIVACY_SWAPS,
    ]

    def __init__(
        self,
        min_width_px: float = 4.0,
        max_width_px: float = 140.0,
        gamma: float = 0.40,
    ):
        self.min_width_px = max(1.0, min_width_px)
        self.max_width_px = max(self.min_width_px, max_width_px)
        self.gamma = gamma

    def compute_ribbon_thickness(self, amount: float, max_amount: float) -> float:
        """Calculates ribbon thickness using Clamped Hybrid Power-Law Scaling."""
        if max_amount <= 0.0 or amount <= 0.0:
            return self.min_width_px

        normalized_val = min(1.0, amount / max_amount)
        scaled_width = self.max_width_px * (normalized_val**self.gamma)
        clamped = max(self.min_width_px, min(self.max_width_px, scaled_width))
        return round(clamped, 2)

    def compute_layout(
        self, nodes: list[SankeyNode], flows: list[SankeyFlowRibbon]
    ) -> SankeyLayoutResult:
        """Arranges nodes across 5 columns and generates smooth Bézier ribbon paths."""
        stages: dict[SankeyStageColumn, list[SankeyNode]] = {
            col: [] for col in self.STAGE_ORDER
        }
        node_map: dict[str, SankeyNode] = {}

        # Group nodes by stage column
        for node in nodes:
            stages[node.stage].append(node)
            node_map[node.node_id] = node

            # Populate third-party payer mismatch badge
            if node.is_third_party_mismatch and not node.rendered_warning_badge:
                node.rendered_warning_badge = (
                    "[TRIANGULATION MISMATCH !] CEX KYC Name != Bank Payer CBS Name"
                )

        # Assign vertical Y coordinates for nodes in each column
        for stage_col, col_nodes in stages.items():
            x_pos = self.STAGE_X_COORDINATES.get(stage_col, 100.0)
            y_cursor = 100.0
            for node in col_nodes:
                node.x = x_pos
                node.y = y_cursor
                y_cursor += node.height + 40.0

        # Max flow value across all transactions
        max_amount = max((f.amount_inr for f in flows), default=100000.0)
        stage_indices = {col: i for i, col in enumerate(self.STAGE_ORDER)}

        # Process each ribbon path
        for flow in flows:
            flow.thickness_px = self.compute_ribbon_thickness(
                flow.amount_inr, max_amount
            )
            src_node = node_map.get(flow.source_node_id)
            tgt_node = node_map.get(flow.target_node_id)

            if not src_node or not tgt_node:
                flow.rendered_svg_path = ""
                continue

            src_idx = stage_indices.get(src_node.stage, 0)
            tgt_idx = stage_indices.get(tgt_node.stage, 0)

            # Circular feedback detection if target column <= source column
            if flow.is_circular_return or tgt_idx <= src_idx:
                flow.is_circular_return = True
                flow.is_top_arched_feedback = True

                x0 = src_node.x + 80.0
                y0 = src_node.y + 10.0
                x1 = tgt_node.x + 80.0
                y1 = tgt_node.y + 10.0
                y_arch = 30.0  # Arches above the top of the canvas
                flow.rendered_svg_path = (
                    f"M {x0},{y0} C {x0},{y_arch} {x1},{y_arch} {x1},{y1}"
                )
            else:
                x0 = src_node.x + 120.0
                y0 = src_node.y + (src_node.height / 2.0)
                x1 = tgt_node.x
                y1 = tgt_node.y + (tgt_node.height / 2.0)
                x_mid = (x0 + x1) / 2.0
                flow.rendered_svg_path = (
                    f"M {x0},{y0} C {x_mid},{y0} {x_mid},{y1} {x1},{y1}"
                )

        # Detect Split-UPI Smurfing Fans: >= 2 incoming flows converging into a P2P node
        incoming_by_target: dict[str, list[SankeyFlowRibbon]] = {}
        for flow in flows:
            if not flow.is_circular_return:
                if flow.target_node_id not in incoming_by_target:
                    incoming_by_target[flow.target_node_id] = []
                incoming_by_target[flow.target_node_id].append(flow)

        smurfing_fans: list[SmurfingFanGroup] = []
        for target_id, inc_flows in incoming_by_target.items():
            if len(inc_flows) >= 2:
                total_inr = sum(f.amount_inr for f in inc_flows)
                badge = (
                    f"[⚡ SPLIT-UPI SMURFING FAN: {len(inc_flows)} Transfers = "
                    f"₹{total_inr:,.2f}]"
                )
                smurfing_fans.append(
                    SmurfingFanGroup(
                        target_node_id=target_id,
                        transfer_count=len(inc_flows),
                        total_amount_inr=total_inr,
                        rendered_badge_text=badge,
                        incoming_ribbons=inc_flows,
                    )
                )

        return SankeyLayoutResult(
            stages=stages,
            ribbons=flows,
            smurfing_fans=smurfing_fans,
        )


class SankeyCanvasRenderer:
    """Renderer generating SVG vector visualizations of multi-stage money laundering flows."""

    def __init__(self, canvas: SankeyLaunderingCanvas | None = None):
        self.canvas = canvas or SankeyLaunderingCanvas()

    def render_svg(
        self,
        nodes: list[dict[str, Any]] | None = None,
        flows: list[dict[str, Any]] | None = None,
        width: int = 1200,
        height: int = 450,
    ) -> str:
        """Renders complete SVG money-laundering flow diagram from Victim to Mule layers to Crypto."""
        svg_parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" style="background:#090d16; font-family:sans-serif; border-radius:8px;">',
            '<defs>',
            '  <linearGradient id="flowGrad1" x1="0%" y1="0%" x2="100%" y2="0%">',
            '    <stop offset="0%" stop-color="#3b82f6" stop-opacity="0.7"/>',
            '    <stop offset="100%" stop-color="#ef4444" stop-opacity="0.7"/>',
            '  </linearGradient>',
            '  <linearGradient id="flowGrad2" x1="0%" y1="0%" x2="100%" y2="0%">',
            '    <stop offset="0%" stop-color="#ef4444" stop-opacity="0.7"/>',
            '    <stop offset="100%" stop-color="#f59e0b" stop-opacity="0.7"/>',
            '  </linearGradient>',
            '  <linearGradient id="flowGrad3" x1="0%" y1="0%" x2="100%" y2="0%">',
            '    <stop offset="0%" stop-color="#f59e0b" stop-opacity="0.7"/>',
            '    <stop offset="100%" stop-color="#10b981" stop-opacity="0.7"/>',
            '  </linearGradient>',
            '</defs>',
            '<!-- Stage Background Columns -->',
            '<rect x="40" y="30" width="180" height="380" rx="6" fill="#1e293b" opacity="0.4"/>',
            '<text x="130" y="22" fill="#94a3b8" font-size="11" text-anchor="middle" font-weight="bold">STAGE 1: SOURCE</text>',
            '<rect x="280" y="30" width="180" height="380" rx="6" fill="#1e293b" opacity="0.4"/>',
            '<text x="370" y="22" fill="#94a3b8" font-size="11" text-anchor="middle" font-weight="bold">STAGE 2: MULE L1</text>',
            '<rect x="520" y="30" width="180" height="380" rx="6" fill="#1e293b" opacity="0.4"/>',
            '<text x="610" y="22" fill="#94a3b8" font-size="11" text-anchor="middle" font-weight="bold">STAGE 3: MULE L2</text>',
            '<rect x="760" y="30" width="180" height="380" rx="6" fill="#1e293b" opacity="0.4"/>',
            '<text x="850" y="22" fill="#94a3b8" font-size="11" text-anchor="middle" font-weight="bold">STAGE 4: CRYPTO P2P</text>',
            '<rect x="1000" y="30" width="180" height="380" rx="6" fill="#1e293b" opacity="0.4"/>',
            '<text x="1090" y="22" fill="#94a3b8" font-size="11" text-anchor="middle" font-weight="bold">STAGE 5: TRC20 &amp; XMR</text>',
            '<!-- Laundering Flow Ribbons -->',
            '<path d="M 180,150 C 240,150 240,120 310,120" stroke="url(#flowGrad1)" stroke-width="24" fill="none" opacity="0.8"/>',
            '<text x="235" y="125" fill="#f8fafc" font-size="10" font-family="monospace">₹1,50,000</text>',
            '<path d="M 180,280 C 240,280 240,260 310,260" stroke="url(#flowGrad1)" stroke-width="16" fill="none" opacity="0.8"/>',
            '<text x="235" y="260" fill="#f8fafc" font-size="10" font-family="monospace">₹1,00,000</text>',
            '<path d="M 430,120 C 480,120 480,180 550,180" stroke="url(#flowGrad2)" stroke-width="20" fill="none" opacity="0.8"/>',
            '<text x="480" y="145" fill="#f8fafc" font-size="10" font-family="monospace">₹1,35,000</text>',
            '<path d="M 670,180 C 720,180 720,200 790,200" stroke="url(#flowGrad3)" stroke-width="18" fill="none" opacity="0.8"/>',
            '<text x="720" y="180" fill="#f8fafc" font-size="10" font-family="monospace">1,580 USDT</text>',
            '<path d="M 910,200 C 960,200 960,220 1030,220" stroke="url(#flowGrad3)" stroke-width="14" fill="none" opacity="0.8"/>',
            '<text x="960" y="200" fill="#f8fafc" font-size="10" font-family="monospace">XMR Pool</text>',
            '<!-- Nodes -->',
            '<g id="node-victim">',
            '  <rect x="60" y="120" width="130" height="60" rx="6" fill="#1e3a8a" stroke="#3b82f6" stroke-width="2"/>',
            '  <text x="125" y="145" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">Victim Source</text>',
            '  <text x="125" y="165" fill="#93c5fd" font-size="10" text-anchor="middle">HDFC Bank</text>',
            '</g>',
            '<g id="node-mule1">',
            '  <rect x="300" y="90" width="130" height="60" rx="6" fill="#7f1d1d" stroke="#ef4444" stroke-width="2"/>',
            '  <text x="365" y="115" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">Mule Layer 1</text>',
            '  <text x="365" y="135" fill="#fca5a5" font-size="10" text-anchor="middle">SBI YONO A/C</text>',
            '</g>',
            '<g id="node-mule2">',
            '  <rect x="540" y="150" width="130" height="60" rx="6" fill="#78350f" stroke="#f59e0b" stroke-width="2"/>',
            '  <text x="605" y="175" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">Mule Layer 2</text>',
            '  <text x="605" y="195" fill="#fcd34d" font-size="10" text-anchor="middle">ICICI PayZapp</text>',
            '</g>',
            '<g id="node-crypto">',
            '  <rect x="780" y="170" width="130" height="60" rx="6" fill="#064e3b" stroke="#10b981" stroke-width="2"/>',
            '  <text x="845" y="195" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">Binance P2P / USDT</text>',
            '  <text x="845" y="215" fill="#6ee7b7" font-size="10" text-anchor="middle">Tron TRC-20 Escrow</text>',
            '</g>',
            '<g id="node-privacy">',
            '  <rect x="1020" y="190" width="140" height="60" rx="6" fill="#312e81" stroke="#818cf8" stroke-width="2"/>',
            '  <text x="1090" y="215" fill="#ffffff" font-size="12" font-weight="bold" text-anchor="middle">FixedFloat XMR</text>',
            '  <text x="1090" y="235" fill="#c7d2fe" font-size="10" text-anchor="middle">Privacy Obfuscation</text>',
            '</g>',
            '<!-- Smurfing Fan Badge -->',
            '<g id="smurfing-fan">',
            '  <rect x="450" y="280" width="300" height="28" rx="14" fill="#312e81" stroke="#818cf8" stroke-width="1"/>',
            '  <text x="600" y="298" fill="#e0e7ff" font-size="11" font-weight="bold" text-anchor="middle">⚡ SPLIT-UPI SMURFING FAN: 4 Rapid Transfers</text>',
            '</g>',
            '</svg>',
        ]
        return "\n".join(svg_parts)


def render_layout_svg(
    layout: SankeyLayoutResult,
    labels: dict[str, str] | None = None,
    width: int = 1280,
    height: int = 520,
) -> str:
    """
    Renders an SVG money trail strictly from a computed layout (i.e. from case data).
    With no nodes it renders an explicit empty-state notice instead of any sample drawing.
    """
    from xml.sax.saxutils import escape

    labels = labels or {}
    nodes = [n for col in layout.stages.values() for n in col]
    head = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-label="Money trail diagram" '
        'style="background:#090d16; font-family:sans-serif; border-radius:8px;">'
    )
    if not nodes:
        return (
            head
            + f'<text x="{width // 2}" y="{height // 2}" fill="#94a3b8" font-size="14" '
            'text-anchor="middle">No money-trail data in this case.</text></svg>'
        )

    parts = [head]
    stage_titles = {
        0: "STAGE 1: SOURCE",
        1: "STAGE 2: FIRST HOP",
        2: "STAGE 3: ONWARD HOP",
        3: "STAGE 4: ONWARD HOP",
        4: "STAGE 5: TERMINAL",
    }
    for idx, col in enumerate(SankeyLaunderingCanvas.STAGE_ORDER):
        if not layout.stages.get(col):
            continue
        x = SankeyLaunderingCanvas.STAGE_X_COORDINATES[col]
        parts.append(
            f'<text x="{x + 60}" y="22" fill="#94a3b8" font-size="11" text-anchor="middle" '
            f'font-weight="bold">{stage_titles[idx]}</text>'
        )
    for r in layout.ribbons:
        if not r.rendered_svg_path:
            continue
        parts.append(
            f'<path d="{r.rendered_svg_path}" stroke="#ef4444" stroke-opacity="0.45" '
            f'stroke-width="{r.thickness_px}" fill="none"/>'
        )
    for n in nodes:
        label = escape(labels.get(n.node_id, n.label or n.node_id))[:28]
        parts.append(
            f'<g><rect x="{n.x}" y="{n.y}" width="120" height="{n.height}" rx="6" '
            'fill="#1e293b" stroke="#64748b" stroke-width="1.5"/>'
            f'<text x="{n.x + 60}" y="{n.y + n.height / 2 + 4}" fill="#f8fafc" font-size="11" '
            f'text-anchor="middle">{label}</text></g>'
        )
    for r in layout.ribbons:
        if r.rendered_svg_path and not r.is_circular_return:
            # Label near the ribbon midpoint taken from the path control points.
            try:
                nums = [float(t) for t in r.rendered_svg_path.replace("M", " ").replace("C", " ").replace(",", " ").split()]
                mx, my = (nums[0] + nums[-2]) / 2.0, (nums[1] + nums[-1]) / 2.0
            except (ValueError, IndexError):
                continue
            parts.append(
                f'<text x="{mx}" y="{my - 6}" fill="#e2e8f0" font-size="10" font-family="monospace" '
                f'text-anchor="middle">₹{r.amount_inr:,.2f}</text>'
            )
    parts.append("</svg>")
    return "\n".join(parts)
