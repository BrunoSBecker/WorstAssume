/**
 * WorstAssume Logo — Cloud split by a diagonal breach line,
 * each half slightly offset. Inline SVG, no file dependency.
 */
export default function Logo({ size = 32, className = '' }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-label="WorstAssume logo"
    >
      <defs>
        <clipPath id="wa-top-clip">
          {/* Everything ABOVE the diagonal cut (top-right half) */}
          <polygon points="0,0 64,0 64,64 0,64" />
        </clipPath>
        {/* Glow filter on the breach line */}
        <filter id="wa-glow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="1.5" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      {/*
        Cloud silhouette split into two halves along a diagonal line
        from (10, 24) to (54, 40).
        Top-right half shifted +2px up, -1px right.
        Bottom-left half shifted -2px down, +1px left.
      */}

      {/* ── TOP-RIGHT half (shifted UP-RIGHT by 2,−2) ── */}
      <g transform="translate(1,-2)">
        <path
          d="
            M 46 30
            C 52 30 56 26 56 21
            C 56 16 52 12 47 12
            C 46 8 42 5 37 5
            C 34 5 31 6 29 8
            C 27 7 25 6 22 6
            C 17 6 13 10 13 15
            C 10 15 8 17 8 20
            C 8 24 11 26 14 27
            L 14 30
            Z
          "
          fill="#6182AB"
          opacity="0.95"
        />
        {/* Clip to only show pixels ABOVE the diagonal cut */}
        <clipPath id="wa-upper">
          <polygon points="64,-5 64,36 0,22 0,-5" />
        </clipPath>
        <path
          d="
            M 46 30
            C 52 30 56 26 56 21
            C 56 16 52 12 47 12
            C 46 8 42 5 37 5
            C 34 5 31 6 29 8
            C 27 7 25 6 22 6
            C 17 6 13 10 13 15
            C 10 15 8 17 8 20
            C 8 24 11 26 14 27
            L 14 30
            Z
          "
          fill="#7aa3c8"
          clipPath="url(#wa-upper)"
        />
      </g>

      {/* ── BOTTOM-LEFT half (shifted DOWN-LEFT by -1,+2) ── */}
      <g transform="translate(-1,2)">
        <path
          d="
            M 8 30
            L 8 34
            C 8 37 11 39 14 39
            L 50 39
            C 53 39 56 37 56 34
            L 56 30
            L 8 30
            Z
          "
          fill="#4e6f8c"
          opacity="0.95"
        />
        <clipPath id="wa-lower">
          <polygon points="64,36 64,70 0,70 0,22" />
        </clipPath>
        <path
          d="
            M 8 30
            L 8 34
            C 8 37 11 39 14 39
            L 50 39
            C 53 39 56 37 56 34
            L 56 30
            L 8 30
            Z
          "
          fill="#6182AB"
          opacity="0.9"
          clipPath="url(#wa-lower)"
        />
      </g>

      {/* ── Breach line glowing in brand blue ── */}
      <line
        x1="6"   y1="21"
        x2="58"  y2="39"
        stroke="#4C94EB"
        strokeWidth="1.6"
        strokeLinecap="round"
        filter="url(#wa-glow)"
        opacity="0.9"
      />
    </svg>
  )
}
