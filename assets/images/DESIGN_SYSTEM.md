# REFLEX Framework Visual Design System

## Icon & Image Strategy

### 1. Free Cybersecurity Icon Libraries

#### **Security-Focused Icon Sets**
- **[Feather Icons](https://feathericons.com/)** - Clean, minimal security icons
  - `shield`, `eye`, `lock`, `alert-triangle`, `search`, `activity`
- **[Hero Icons](https://heroicons.com/)** - Modern security icons
  - `ShieldCheckIcon`, `EyeIcon`, `LockClosedIcon`, `ExclamationTriangleIcon`
- **[Tabler Icons](https://tabler-icons.io/)** - Extensive security collection
  - `shield-check`, `eye-check`, `lock`, `alert-circle`, `search`, `activity`
- **[Phosphor Icons](https://phosphoricons.com/)** - Security & tech theme
  - `Shield`, `Eye`, `Lock`, `Warning`, `MagnifyingGlass`, `Activity`

#### **Specialized Security Icons**
- **[Security Icons by Icons8](https://icons8.com/icons/set/security)** - Comprehensive security set
- **[Cybersecurity Vectors - Freepik](https://www.freepik.com/free-vectors/cybersecurity)** - Free vectors
- **[Flaticon Security Collection](https://www.flaticon.com/categories/security)** - Large security icon library

### 2. AI-Generated Custom Icons

#### **Recommended AI Tools**
- **[Midjourney](https://midjourney.com/)** - High-quality custom icons
  ```
  Prompts: "minimalist cybersecurity icon, shield with circuit pattern, dark blue and cyan, vector style"
  ```
- **[DALL-E 3](https://openai.com/dall-e-3)** - Custom security illustrations
- **[Ideogram](https://ideogram.ai/)** - Good for technical diagrams
- **[Adobe Firefly](https://firefly.adobe.com/)** - Commercial-safe AI generation

#### **Custom Generation Prompts**
```
🔍 Reconnaissance: "minimalist search magnifying glass icon, cybersecurity theme, dark navy and cyan, vector style, 64px"

📊 Evaluate: "assessment chart icon, security analysis, dark blue and purple gradient, minimal vector"

🛡️ Fortify: "shield protection icon, cybersecurity defense, dark theme with green accent, clean vector"

⚡ Limit: "containment barrier icon, red warning theme, minimal security vector"

👁️ Expose: "monitoring eye icon, surveillance theme, yellow accent, clean vector style"

💪 Exercise: "training target icon, practice theme, pink accent, minimal vector"
```

### 3. REFLEX Stage Icon System

#### **Primary Stage Icons**
```
/assets/images/icons/stages/
├── 01-reconnaissance.svg        # 🔍 Cyan theme
├── 02-evaluate.svg             # 📊 Purple theme
├── 03-fortify.svg              # 🛡️ Green theme
├── 04-limit.svg                # ⚡ Red theme
├── 05-expose.svg               # 👁️ Yellow theme
└── 06-exercise.svg             # 💪 Pink theme
```

#### **Icon Variations Needed**
- **Primary**: Full color with glow effects
- **Monochrome**: Single color versions
- **Outline**: Stroke-only versions
- **Small**: 16px, 24px, 32px
- **Large**: 64px, 128px, 256px

### 4. CVE & Threat Level Icons

#### **Severity Levels**
```
/assets/images/icons/severity/
├── critical.svg                # Red, urgent styling
├── high.svg                    # Orange, high priority
├── medium.svg                  # Yellow, moderate
└── low.svg                     # Blue, informational
```

#### **Vulnerability Types**
```
/assets/images/icons/vulnerabilities/
├── supply-chain.svg            # Package/dependency theme
├── code-injection.svg          # Code brackets with warning
├── authentication.svg          # Lock with X or warning
├── authorization.svg           # Shield with user icon
├── cryptographic.svg           # Key with warning
└── denial-of-service.svg       # Traffic/network with X
```

### 5. Technology & Tool Icons

#### **Languages & Frameworks**
```
/assets/images/icons/tech/
├── javascript.svg              # Node.js ecosystem
├── python.svg                  # Python ecosystem
├── java.svg                    # Java ecosystem
├── go.svg                      # Go ecosystem
├── rust.svg                    # Rust ecosystem
├── docker.svg                  # Containerization
├── kubernetes.svg              # Orchestration
└── github-actions.svg          # CI/CD
```

### 6. Battlecard Category Icons

#### **Attack Vector Categories**
```
/assets/images/icons/categories/
├── supply-chain.svg            # Package/link chain
├── social-engineering.svg     # Person with warning
├── infrastructure.svg          # Server/cloud with shield
├── ai-ml.svg                   # Brain/neural network
└── ci-cd.svg                   # Pipeline with gear
```

### 7. Design Guidelines

#### **Color Palette Application**
- **Reconnaissance (🔍)**: `#a1d6e8` - Cyan discovery
- **Evaluate (📊)**: `#9d79ff` - Purple analysis
- **Fortify (🛡️)**: `#37eb5f` - Green protection
- **Limit (⚡)**: `#ff4c4c` - Red containment
- **Expose (👁️)**: `#ffd700` - Yellow visibility
- **Exercise (💪)**: `#ff79c6` - Pink training

#### **Style Requirements**
- **Format**: SVG preferred (scalable, small file size)
- **Style**: Minimal, clean, cybersecurity theme
- **Stroke width**: 2px for outline icons
- **Corner radius**: 6px for containers/boxes
- **Glow effects**: Using CSS filters, not baked into SVG

#### **Naming Convention**
- Use kebab-case: `supply-chain-attack.svg`
- Include category: `stage-01-reconnaissance.svg`
- Include size if multiple: `shield-icon-64px.svg`

### 8. Implementation Strategy

#### **Phase 1: Core Icons (Week 1)**
1. Generate 6 REFLEX stage icons
2. Create 4 severity level icons
3. Set up basic vulnerability type icons

#### **Phase 2: Expansion (Week 2)**
1. Technology ecosystem icons
2. Battlecard category icons
3. UI/UX icons (arrows, buttons, etc.)

#### **Phase 3: Specialized Content (Week 3)**
1. Custom CVE-specific diagrams
2. Attack flow illustrations
3. Architecture diagrams

### 9. Tools for Icon Management

#### **Design Tools**
- **[Figma](https://figma.com)** - Free, collaborative icon design
- **[Canva](https://canva.com)** - Templates and easy editing
- **[GIMP](https://gimp.org)** - Free alternative to Photoshop

#### **SVG Optimization**
- **[SVGO](https://github.com/svg/svgo)** - Optimize SVG files
- **[SVGOMG](https://jakearchibald.github.io/svgomg/)** - Web-based SVG optimizer

#### **Icon Organization Tools**
- **[Iconify](https://iconify.design/)** - Icon framework for web
- **[Nucleo App](https://nucleoapp.com/)** - Icon management software

### 10. Legal Considerations

#### **License Requirements**
- **Free icons**: Check attribution requirements
- **Commercial use**: Verify commercial licensing
- **AI-generated**: Ensure tools provide commercial rights
- **Custom icons**: Document creation source and rights

#### **Recommended Safe Sources**
- **Public Domain**: No attribution required
- **MIT/Apache Licensed**: Attribution in code comments
- **Creative Commons CC0**: No rights reserved
- **Purchased licenses**: Keep receipts and license terms