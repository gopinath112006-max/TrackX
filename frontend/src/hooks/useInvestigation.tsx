import { createContext, useContext, useState, ReactNode } from 'react'

interface InvestigationContextValue {
  investigationId: number | null
  investigationName: string | null
  setInvestigation: (id: number, name: string) => void
}

const InvestigationContext = createContext<InvestigationContextValue>({
  investigationId: null,
  investigationName: null,
  setInvestigation: () => {},
})

export function InvestigationProvider({ children }: { children: ReactNode }) {
  const [investigationId, setInvestigationId] = useState<number | null>(null)
  const [investigationName, setInvestigationName] = useState<string | null>(null)

  const setInvestigation = (id: number, name: string) => {
    setInvestigationId(id)
    setInvestigationName(name)
  }

  return (
    <InvestigationContext.Provider value={{ investigationId, investigationName, setInvestigation }}>
      {children}
    </InvestigationContext.Provider>
  )
}

export function useInvestigation() {
  return useContext(InvestigationContext)
}